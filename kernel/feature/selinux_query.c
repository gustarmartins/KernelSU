#if IS_BUILTIN(CONFIG_KSU)
/* Follow the existing non-root app policy; do not alter root or system views. */
bool ksu_compat_query_eligible(void)
{
    uid_t uid = __kuid_val(current_uid());
    uid_t appid = uid % PER_USER_RANGE;

    if (!uid_eq(current_uid(), current_euid()) || appid < 10000 || appid >= 20000)
        return false;
    return ksu_uid_should_umount(uid);
}

static int selinux_query_feature_get(u64 *value)
{
    *value = security_compat_get_enabled() ? 1 : 0;
    return 0;
}

static int selinux_query_feature_set(u64 value)
{
    if (value > 1)
        return -EINVAL;
    return security_compat_set_enabled(value != 0);
}

static const struct ksu_feature_handler selinux_query_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_query_feature_get,
    .set_handler = selinux_query_feature_set,
};

static void __init ksu_selinux_query_init(void)
{
    if (ksu_register_feature_handler(&selinux_query_handler))
        pr_err("Failed to register scoped SELinux query feature\n");
}
#endif
