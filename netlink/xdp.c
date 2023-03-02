/*
 * xdp.c - netlink implementation of xdp features commands
 *
 * Implementation of "ethtool --get-xdp-features <dev>".
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "bitset.h"

static bool xdp_feature_on(const uint32_t *bitmap, unsigned int index)
{
	return bitmap[index / 32] & (1 << (index % 32));
}

static int dump_xdp_features(const struct nlattr *const *tb,
			     const struct stringset *feature_names)
{
	uint32_t *features;
	int err, count, i;

	if (!tb[ETHTOOL_A_XDP_FEATURES_DATA])
		return -EFAULT;

	count = bitset_get_count(tb[ETHTOOL_A_XDP_FEATURES_DATA], &err);
	if (err < 0)
		return -EFAULT;

	features = get_compact_bitset_value(tb[ETHTOOL_A_XDP_FEATURES_DATA]);
	if (!features)
		return -EFAULT;

	for (i = 0; i < count; i++) {
		const char *name = get_string(feature_names, i);

		if (!name || !*name)
			continue;

		printf("%s: %s\n", name,
		       xdp_feature_on(features, i) ? "supported" : "not-supported");
	}

	return 0;
}

int xdp_features_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_XDP_FEATURES_MAX + 1] = {};
	const struct stringset *xdp_feature_names;
	struct nl_context *nlctx = data;
	DECLARE_ATTR_TB_INFO(tb);
	bool silent;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	if (!nlctx->is_monitor) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return MNL_CB_ERROR;
	}

	xdp_feature_names = global_stringset(ETH_SS_XDP_FEATURES,
					     nlctx->ethnl2_socket);

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return silent ? MNL_CB_OK : MNL_CB_ERROR;

	nlctx->devname = get_dev_name(tb[ETHTOOL_A_XDP_FEATURES_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (silent)
		putchar('\n');

	print_string(PRINT_ANY, "ifname", "XDP features for %s:\n",
		     nlctx->devname);
	ret = dump_xdp_features(tb, xdp_feature_names);

	return (silent || !ret) ? MNL_CB_OK : MNL_CB_ERROR;
}

int nl_get_xdp_features(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_XDP_FEATURES_GET, false))
		return -EOPNOTSUPP;

	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_XDP_FEATURES_GET,
				      ETHTOOL_A_XDP_FEATURES_HEADER,
				      ETHTOOL_FLAG_COMPACT_BITSETS);
	if (ret < 0)
		return ret;

	return nlsock_send_get_request(nlsk, xdp_features_reply_cb);
}
