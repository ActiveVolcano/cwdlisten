#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>
#include <iso646.h>

/*
Obtains the current working directory (CWD)
of the process listening on the specified TCP port
in Linux.

Author:
CHEN Qingcan, 2024 spring, Foshan Nanhai China.

Build:
cc -std=gnu11 -Wall -s -o cwdlisten cwdlisten.c
*/

bool VERBOSE = false;

//----------------------------------------------------------------------------
void die (const char* say) {
	puts (say);
	exit (EXIT_FAILURE);
}

//----------------------------------------------------------------------------
void usage () {
	puts ("Usage: cwdlisten [-v|--verbose] {port}");
	exit (EXIT_SUCCESS);
}

//----------------------------------------------------------------------------
// Returns port.
long parseArgs (int argc, const char** argv) {
	if (argc < 2) usage ();
	long port = 0;
	for (int i = 1 ; i < argc ; i++) {
		if      (strcmp (argv[i], "-h"    ) == 0) usage ();
		else if (strcmp (argv[i], "--help") == 0) usage ();
		else if (strcmp (argv[i], "help"  ) == 0) usage ();
		else if (strcmp (argv[i], "-v"       ) == 0) VERBOSE = true;
		else if (strcmp (argv[i], "--verbose") == 0) VERBOSE = true;
		else if ((port = atol (argv[i])) <= 0) usage ();
	}
	if (port <= 0) usage ();
	return port;
}

//----------------------------------------------------------------------------
char* getExecOutput1Line (const char* cmd, char* output1line, const size_t len) {
	if (cmd == NULL or output1line == NULL or len <= 0) die ("NULL getExecOutput1Line");
	if (VERBOSE) puts (cmd);

	FILE* output = popen (cmd, "r");
	if (output == NULL) die (strerror (errno));

	output1line[0] = '\0';
	if (fgets (output1line, len, output) == NULL) die ("NULL output");
	if (VERBOSE) fputs (output1line, stdout);

	if (ferror (output)) perror ("ferror");
	if (pclose (output) == -1) perror ("pclose");
	if (output1line[0] == '\0') die ("empty output");
	return output1line;
}

//----------------------------------------------------------------------------
long getPIDfromNetstat (char* netstat) {
	if (netstat == NULL) die ("NULL getPIDfromNetstat");
	char *token, *saveptr;

	token = strtok_r (netstat, " ", &saveptr);
	for (int column = 1 ; column < 7 and token != NULL ; column++) token = strtok_r (NULL, " ", &saveptr);
	if (token == NULL) die ("NULL strtok_r");

	long pid = atol (token);
	if (VERBOSE) printf ("PID = %ld\n", pid);
	if (pid == 0) die ("PID 0");
	return pid;
}

//----------------------------------------------------------------------------
char* getCWDfromPID (const long pid, char* cwd, const size_t len) {
	if (pid == 0 or cwd == NULL or len <= 0) die ("NULL getCWDfromPID");

	char path [PATH_MAX];
	sprintf (path, "/proc/%ld/cwd", pid);
	ssize_t read = readlink (path, cwd, len - 1);
	if (read != -1) {
		cwd [read] = '\0';
		if (VERBOSE) printf ("readlink %s -> %s \n", path, cwd);
		return cwd;
	}

	perror ("readlink");
	die ("");
	return NULL;
}

//----------------------------------------------------------------------------
int main (int argc, const char** argv) {
	long port = parseArgs (argc, argv);
	char cmd [BUFSIZ], line [BUFSIZ];

	sprintf (cmd, "netstat -pan | grep ':%ld .*LISTEN'", port);
	getExecOutput1Line (cmd, line, sizeof (line));

	long pid = getPIDfromNetstat (line);

	sprintf (cmd, "file /proc/%ld/cwd", pid);
	getCWDfromPID (pid, line, sizeof (line));

	puts (line);
	return EXIT_SUCCESS;
}
