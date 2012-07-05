#include "osx.h"

int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (setuid(ruid))
		return -1;
	if (seteuid(euid))
		return -1;
	return 0;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (setgid(rgid))
		return -1;
	if (setegid(egid))
		return -1;
	return 0;
}
