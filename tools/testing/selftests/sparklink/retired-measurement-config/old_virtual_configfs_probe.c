	int policy = open("/sys/kernel/config/sparklink/power_mode", O_RDWR);
	CHECK(policy >= 0);
	char mode[16]; CHECK(read(policy, mode, sizeof(mode)) == -1 && errno == EOPNOTSUPP);
	CHECK(write(policy, "idle\n", 5) == -1 && errno == EOPNOTSUPP);
	CHECK(!close(policy));
	printf("VIRTUAL_GLOBAL_POWER_POLICY_PASS: show=EOPNOTSUPP store=EOPNOTSUPP\n");
