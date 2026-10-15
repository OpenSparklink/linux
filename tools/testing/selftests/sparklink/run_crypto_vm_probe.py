#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/sign actual crypto test module and boot an isolated VM; never host insmod/USB."""
import argparse, gzip, hashlib, json, os, re, shutil, subprocess, time
from pathlib import Path

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['kernel-build','kernel-artifacts','qemu','busybox','signing-key','signing-cert','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--timeout',type=int,default=180)
    a=p.parse_args()
    if not 10<=a.timeout<=300:p.error('timeout10..300 required')
    here=Path(__file__).resolve().parent;source=here.parents[3]
    identity=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    scope=['net/sparklink/sle_crypto_ffi.c','net/sparklink/sle_pair_crypto.c','net/sparklink/sle_pair_material.c','net/sparklink/sle_pair_material.h',str((here/'security/crypto_vm_probe.c').relative_to(source)),str(Path(__file__).relative_to(source))]
    if subprocess.check_output(['git','status','--porcelain','--',*scope],cwd=source):raise RuntimeError('probe source scope must be committed and clean')
    a.kernel_build=a.kernel_build.resolve();a.output=a.output.resolve();a.output.mkdir(mode=0o700)
    artifacts=json.loads(a.kernel_artifacts.read_text());assert artifacts['status']=='NATIVE_BUILD_ARTIFACTS_VERIFIED'
    for key in ['.config','Module.symvers','arch/x86/boot/bzImage','include/config/kernel.release']:
        assert digest(a.kernel_build/key)==artifacts['inputs'][key]['sha256'],key
    record={'status':'BUILDING','scope':'actual kernel crypto only; no WS73 USB, pairing, trusted authentication or encryption qualification','probe_source_head':identity,'boot_kernel_head':artifacts['source_head'],'source_mapping':{name:digest(source/name) for name in scope},'kernel_artifact_manifest_sha256':digest(a.kernel_artifacts),'vm_only':True,'usb_passthrough':False,'signing_certificate_sha256':digest(a.signing_cert),'physical_security_acceptance':False}
    manifest=a.output/'manifest.json'
    def save():manifest.write_text(json.dumps(record,indent=2)+'\n')
    save();build=a.output/'module';build.mkdir()
    (build/'probe.c').write_text('#include "'+str(here/'security/crypto_vm_probe.c')+'"\n')
    (build/'Makefile').write_text('obj-m := sparklink_crypto_probe.o\nsparklink_crypto_probe-y := probe.o\nccflags-y += -Werror\n')
    try:
        with (a.output/'build.log').open('w') as log:subprocess.run(['make','LLVM=1','-C',str(a.kernel_build),'M='+str(build),'W=1','modules'],stdout=log,stderr=subprocess.STDOUT,check=True)
        module=build/'sparklink_crypto_probe.ko'
        subprocess.run([str(a.kernel_build/'scripts/sign-file'),'sha256',str(a.signing_key.resolve()),str(a.signing_cert.resolve()),str(module)],check=True)
        record.update(status='BOOTING',module_sha256=digest(module),kernel_release=(a.kernel_build/'include/config/kernel.release').read_text().strip());save()
        root=a.output/'initramfs';root.mkdir()
        for directory in ['bin','dev','proc','sys','tmp']: (root/directory).mkdir()
        shutil.copy2(a.busybox,root/'bin/busybox');shutil.copy2(module,root/'probe.ko')
        (root/'init').write_text('''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
insmod /probe.ko
result=$?
if [ "$result" = 0 ]; then
 echo SPARKLINK_SECURITY_CRYPTO_MODULE_LOADED
 rmmod sparklink_crypto_probe || echo SPARKLINK_SECURITY_CRYPTO_UNLOAD_FAIL
else
 echo SPARKLINK_SECURITY_CRYPTO_MODULE_FAIL:$result
fi
echo SPARKLINK_SECURITY_CRYPTO_TAINT:$(cat /proc/sys/kernel/tainted)
poweroff -f
''');(root/'init').chmod(0o755)
        files=['.']+[str(x.relative_to(root)) for x in sorted(root.rglob('*'))]
        cpio=subprocess.run(['cpio','--null','-o','--format=newc','--owner=0:0'],input=('\0'.join(files)+'\0').encode(),cwd=root,capture_output=True,check=True)
        archive=a.output/'initramfs.cpio.gz';archive.write_bytes(gzip.compress(cpio.stdout,mtime=0))
        command=[str(a.qemu.resolve()),'-machine','q35,accel=kvm','-cpu','host','-m','768','-smp','2','-nodefaults','-display','none','-serial','stdio','-no-reboot','-kernel',str(a.kernel_build/'arch/x86/boot/bzImage'),'-initrd',str(archive),'-append','console=ttyS0 rdinit=/init panic=-1 loglevel=7','-object','rng-random,id=rng0,filename=/dev/urandom','-device','virtio-rng-pci,rng=rng0']
        record['command']=command;record['started_ns']=time.time_ns();save()
        with (a.output/'console.log').open('w') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=a.timeout)
        text=(a.output/'console.log').read_text(errors='replace')
        if result.returncode or text.count('SPARKLINK_SECURITY_CRYPTO_VM_PASS:')!=1 or text.count('SPARKLINK_SECURITY_CRYPTO_MODULE_LOADED')!=1 or any(x in text for x in ['SPARKLINK_SECURITY_CRYPTO_VM_FAIL','SPARKLINK_SECURITY_CRYPTO_MODULE_FAIL','SPARKLINK_SECURITY_CRYPTO_UNLOAD_FAIL','BUG:','Kernel panic','WARNING:','Oops:']):raise RuntimeError('VM terminal verdict failed; inspect original console')
        taints=re.findall(r'SPARKLINK_SECURITY_CRYPTO_TAINT:(\d+)',text)
        if len(taints)!=1 or int(taints[0]) not in (0,4096):raise RuntimeError('unexpected taint; only explicit out-of-tree selftest bit allowed')
        if any(digest(source/name)!=value for name,value in record['source_mapping'].items()):raise RuntimeError('probe source changed during run')
        record.update(status='ACTUAL_KERNEL_CRYPTO_VM_PASS',qemu_exit=result.returncode,taint=int(taints[0]),taint_scope='0 or4096 out-of-tree dedicated selftest; not normal WS73 qualification',console_sha256=digest(a.output/'console.log'),ended_ns=time.time_ns());save();print(json.dumps({k:record[k] for k in ['status','scope','probe_source_head','boot_kernel_head','qemu_exit','taint','physical_security_acceptance']},indent=2))
    except BaseException as error:
        record.update(status='FAIL',error_type=type(error).__name__,error=str(error));save();raise
if __name__=='__main__':main()
