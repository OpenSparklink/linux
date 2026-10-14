/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SL_SECURITY_RELAY_H
#define SL_SECURITY_RELAY_H
void *sl_security_owner_create_rust(unsigned short id, unsigned long long generation,
    unsigned long long lifetime, unsigned short handle, unsigned long long epoch);
void sl_security_owner_stop_rust(void *owner);
void sl_security_owner_destroy_rust(void *owner);
void *sl_connection_session_security(void *session);
#endif
