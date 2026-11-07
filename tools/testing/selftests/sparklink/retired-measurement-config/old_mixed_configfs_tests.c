static void test_configfs(void)
{
	char buf[128];

	test_header("configfs: mount and version");
	/* Ensure configfs is mounted */
	mkdir("/sys/kernel/config", 0755);
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) < 0) {
		if (errno != EBUSY) {
			printf("  OK:   configfs mount skipped (errno=%d)\n", errno);
		}
	}

	if (read_configfs_attr("version", buf, sizeof(buf)) == 0) {
		printf("  OK:   version = %s\n", buf);
	} else {
		test_fail("  FAIL: cannot read version attribute\n");
	}

	test_header("configfs: read defaults");
	if (read_configfs_attr("max_connections", buf, sizeof(buf)) == 0)
		printf("  OK:   max_connections = %s (default)\n", buf);
	else
		test_fail("  FAIL: cannot read max_connections\n");

	if (read_configfs_attr("adv_interval_ms", buf, sizeof(buf)) == 0)
		printf("  OK:   adv_interval_ms = %s (default)\n", buf);
	else
		test_fail("  FAIL: cannot read adv_interval_ms\n");

	if (read_configfs_attr("scan_window_ms", buf, sizeof(buf)) == 0)
		printf("  OK:   scan_window_ms = %s (default)\n", buf);
	else
		test_fail("  FAIL: cannot read scan_window_ms\n");

	if (read_configfs_attr("power_mode", buf, sizeof(buf)) == 0)
		printf("  OK:   power_mode = %s (default)\n", buf);
	else
		test_fail("  FAIL: cannot read power_mode\n");

	if (read_configfs_attr("controller_type", buf, sizeof(buf)) == 0)
		printf("  OK:   controller_type = %s (default)\n", buf);
	else
		test_fail("  FAIL: cannot read controller_type\n");

	test_header("configfs: write and readback");
	if (write_configfs_attr("max_connections", "4") == 0 &&
	    read_configfs_attr("max_connections", buf, sizeof(buf)) == 0 &&
	    strcmp(buf, "4") == 0)
		printf("  OK:   max_connections set to 4\n");
	else
		test_fail("  FAIL: max_connections write/readback\n");

	if (write_configfs_attr("adv_interval_ms", "500") == 0 &&
	    read_configfs_attr("adv_interval_ms", buf, sizeof(buf)) == 0 &&
	    strcmp(buf, "500") == 0)
		printf("  OK:   adv_interval_ms set to 500\n");
	else
		test_fail("  FAIL: adv_interval_ms write/readback\n");

	if (write_configfs_attr("scan_window_ms", "300") == 0 &&
	    read_configfs_attr("scan_window_ms", buf, sizeof(buf)) == 0 &&
	    strcmp(buf, "300") == 0)
		printf("  OK:   scan_window_ms set to 300\n");
	else
		test_fail("  FAIL: scan_window_ms write/readback\n");

	if (write_configfs_attr("power_mode", "sniff") == 0 &&
	    read_configfs_attr("power_mode", buf, sizeof(buf)) == 0 &&
	    strcmp(buf, "sniff") == 0)
		printf("  OK:   power_mode set to sniff\n");
	else
		test_fail("  FAIL: power_mode write/readback\n");

	test_header("configfs: boundary validation");
	/* max_connections: 0 should fail */
	if (write_configfs_attr("max_connections", "0") != 0)
		printf("  OK:   max_connections=0 rejected\n");
	else
		test_fail("  FAIL: max_connections=0 should be rejected\n");

	/* max_connections: 9 should fail */
	if (write_configfs_attr("max_connections", "9") != 0)
		printf("  OK:   max_connections=9 rejected\n");
	else
		test_fail("  FAIL: max_connections=9 should be rejected\n");

	/* adv_interval_ms: 10 should fail (min is 20) */
	if (write_configfs_attr("adv_interval_ms", "10") != 0)
		printf("  OK:   adv_interval_ms=10 rejected (min 20)\n");
	else
		test_fail("  FAIL: adv_interval_ms=10 should be rejected\n");

	/* power_mode: invalid string */
	if (write_configfs_attr("power_mode", "turbo") != 0)
		printf("  OK:   power_mode=turbo rejected\n");
	else
		test_fail("  FAIL: power_mode=turbo should be rejected\n");

	/* Global selector cannot fabricate a registered hardware Backend. */
	const char *unsupported[] = { "uart", "spi", "usb" };
	for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
		errno = 0;
		if (write_configfs_attr("controller_type", unsupported[i]) != 0 &&
		    errno == EOPNOTSUPP &&
		    read_configfs_attr("controller_type", buf, sizeof(buf)) == 0 &&
		    strcmp(buf, "none") == 0)
			printf("  OK:   controller_type=%s explicitly unsupported\n", unsupported[i]);
		else
			test_fail("  FAIL: controller_type fabricates selected hardware\n");
	}

	/* Invalid controller_type */
	if (write_configfs_attr("controller_type", "i2c") != 0)
		printf("  OK:   controller_type=i2c rejected\n");
	else
		test_fail("  FAIL: controller_type=i2c should be rejected\n");

	/* Restore defaults */
	write_configfs_attr("max_connections", "8");
	write_configfs_attr("adv_interval_ms", "100");
	write_configfs_attr("scan_window_ms", "200");
	write_configfs_attr("power_mode", "active");
	write_configfs_attr("controller_type", "none");
}

static void test_configfs_ioctl_integration(int fd)
{
	test_header("configfs-ioctl integration: default parameter fallback");

	/* Set configfs adv_interval_ms to 250 */
	if (write_configfs_attr("adv_interval_ms", "250") != 0) {
		test_fail("  FAIL: cannot set adv_interval_ms=250\n");
		return;
	}
	printf("  OK:   configfs adv_interval_ms set to 250\n");

	/* Set configfs scan_window_ms to 150 */
	if (write_configfs_attr("scan_window_ms", "150") != 0) {
		test_fail("  FAIL: cannot set scan_window_ms=150\n");
		return;
	}
	printf("  OK:   configfs scan_window_ms set to 150\n");

	/* START_ADV with interval_ms=0 should use configfs default (250) */
	set_role(fd, 1); /* GNode */
	struct sle_adv_params adv;

	memset(&adv, 0, sizeof(adv));
	adv.discovery_level = 1;
	adv.interval_ms = 0; /* trigger configfs fallback */
	int ret = ioctl(fd, SL_IOCTL_START_ADV, &adv);

	check("START_ADV (interval_ms=0, configfs fallback)", ret);
	ioctl(fd, SL_IOCTL_STOP_ADV, NULL);

	/* START_SCAN with window_ms=0 should use configfs default (150) */
	set_role(fd, 0); /* TNode */
	struct sle_scan_params scan;

	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 0; /* trigger configfs fallback */
	scan.interval_ms = 0; /* trigger configfs fallback (2x window) */
	scan.filter_discovery_level = 0;
	ret = ioctl(fd, SL_IOCTL_START_SCAN, &scan);
	check("START_SCAN (window_ms=0, configfs fallback)", ret);
	ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);

	/* Restore configfs defaults */
	write_configfs_attr("adv_interval_ms", "100");
	write_configfs_attr("scan_window_ms", "200");

	/* Drain DLI events */
	struct sle_dli_event ev;

	for (int i = 0; i < 32; i++) {
		if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &ev) < 0)
			break;
	}
}

static int write_configfs_attr(const char *name, const char *val)
{
	char path[256];

	snprintf(path, sizeof(path), CONFIGFS_BASE "/%s", name);
	int f = open(path, O_WRONLY);

	if (f < 0)
		return -1;
	ssize_t n = write(f, val, strlen(val));
	int saved_errno = errno;

	close(f);
	errno = saved_errno;
	return n > 0 ? 0 : -1;
}
