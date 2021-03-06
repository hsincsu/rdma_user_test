#ifndef _KRPING_GETOPT_H
#define _KRPING_GETOPT_H

#define OPT_NOPARAM	1
#define OPT_INT		2
#define OPT_STRING	4
struct krdma_option {
	const char *name;
	unsigned int has_arg;
	int val;
};

extern int krdma_getopt(const char *caller, char **options, const struct krdma_option *opts,
		      char **optopt, char **optarg, unsigned long *value);

#endif /* _KRPING_GETOPT_H */