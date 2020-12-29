#include <r_core.h>
#include <r_util.h>


#define handle_skip(s, in) \
	if (*in == '\\') { escape = true;\
	} else if (*in == skip && !escape) { skip = 0;\
	} else { escape = false; }

typedef struct {
	char *cmd;
} RShellHandler;


typedef struct {
	char *cmd;
	char *comment;
} RShellCommand;

typedef struct {
	int repeat;
	RList *args;
	RList *ats;
	RList *fors;
	RList *trifors;
	RShellCommand *sc;
	char *_argstr;
	char *atstr;
} RShellInstruction;

typedef struct {
	// hold configuration and available commands
	RList *stack; // pile of pending commands to be fetched
	char *error;
	PJ *pj;
} RShell;

R_API RShell *r_shell_new(void) {
	return R_NEW0 (RShell);
}

R_API void r_shell_free(RShell *s) {
	r_list_free (s->stack);
	free (s->error);
	free (s);
}

R_API void r_shell_instruction_free(RShellInstruction *s) {
	free (s->_argstr);
	free (s);
}

R_API RShellCommand *r_shell_command_new(const char *ocmd) {
	if (R_STR_ISEMPTY (ocmd)) {
		return NULL;
	}
	RShellCommand *sc = R_NEW0 (RShellCommand);
	sc->cmd = r_str_trim_dup (ocmd);
	return sc;
}

R_API void r_shell_command_free(RShellCommand *s) {
	r_free (s->cmd);
	r_free (s->comment);
}

R_API void r_shell_register(RShell *s, const char *name, RShellHandler *sh) {
}

static RList *shell_parse_split(RShell *s, const char *_cmd) {
	const char *comment = NULL;
	char *pcmd = strdup (_cmd);
	char *cmd = pcmd;
	RList *stack = r_list_newf ((RListFree)r_shell_command_free);
	char *ocmd = cmd;
	int skip = 0;
	int escape = 0;
	while (*cmd) {
		if (skip) {
			handle_skip (s, cmd);
			cmd++;
			continue;
		}
		escape = false;
		switch (*cmd) {
		case '\\':
			escape = true;
			break;
		case '#':
			// comments ends
			*cmd = 0;
			comment = r_str_trim_head_ro (cmd + 1);
			goto beach;
		case '"':
		case '\'':
		case '`':
			skip = *cmd;
			break;
		case '\n':
		case ';': 
			if (!skip) {
				*cmd = 0;
				RShellCommand *c = r_shell_command_new (ocmd);
				if (c) {
					r_list_append (stack, c);
				}
				ocmd = cmd + 1;
			}
			break;
		}
		cmd++;
	}
beach:
	if (skip) {
		free (s->error);
		s->error = r_str_newf ("Missing invalid command%c", 10);
	}
	{
		RShellCommand *c = r_shell_command_new (ocmd);
		if (c) {
			if (comment) {
				c->comment = strdup (comment);
			}
			r_list_append (stack, c);
		}
		free (pcmd);
	}
	return stack;
}

static void shell_split_args(RShellInstruction *si, const char *in) {
	const char *oin = in;
	bool escape = false;
	const char *ats = NULL;
	RList *args = si->args;
	int skip = 0;
	while (*in) {
		if (skip) {
			handle_skip (s, in);
			in++;
			continue;
		}
		switch (*in) {
		case '@': {
			char *a = r_str_ndup (oin, in - oin);
			r_str_trim (a);
			if (!R_STR_ISEMPTY (a)) {
				r_list_append (args, a);
			} else {
				free (a);
			}
			if (in[1] == '@') { // @@
				if (in[2] == '@') { // @@@
					args = si->trifors;
					in += 2;
					oin = in + 1;
				} else {
					args = si->fors;
					in += 1;
					oin = in + 1;
				}
			} else { // @
				args = si->ats;
				oin = in + 1;
			}
			  }
			break;
		case '`':
		case '\'':
		case '"':
			skip = *in;
			break;
		case ' ':
			if (si->args == args) {
				char *a = r_str_ndup (oin, in - oin);
				r_str_trim (a);
				if (!R_STR_ISEMPTY (a)) {
					r_list_append (args, a);
				}
				oin = in + 1;
			}
			break;
		}
		in++;
	}
	if (*oin) {
		r_list_append (args, r_str_ndup (oin, in - oin));
	}
}

R_API RShellInstruction *r_shell_decode(RShell *s, RShellCommand *sc) {
	RShellInstruction *si = R_NEW0 (RShellInstruction);
	si->sc = sc;
	// skip initial digits and set 
	const char *p = sc->cmd;
	while (isdigit (*p)) {
		p++;
	}
	si->repeat = atoi (sc->cmd);
	si->_argstr = strdup (p);
	char *q = strdup (p);
	free (sc->cmd);
	sc->cmd = q;
	const char *ats;
	si->args = r_list_newf (free);
	si->ats = r_list_newf (free);
	si->fors = r_list_newf (free);
	si->trifors = r_list_newf (free);
	shell_split_args (si, si->_argstr);
	return si;
}

R_API char *r_shell_execute(RShell *s, RShellInstruction *si) {
	return r_str_newf (""); // exec('%s', repeat=%d, at='%s')", si->sc->cmd, si->repeat, si->atstr);
}

R_API RShellCommand *r_shell_fetch(RShell *s, const char *cmd) {
	if (cmd) {
		if (s->stack) {
			if (r_list_length (s->stack) > 0) {
				eprintf ("Warning: Pending commands lost.%c", 10);
			}
			r_list_free (s->stack);
		}
		s->stack = shell_parse_split (s, cmd);
	}
	return r_list_pop_head (s->stack);
}

static void run_command(RCore *core, RShell *s, const char *cmd) {
	// TODO: configure shell with proper syntax for command parsing
	s->pj = pj_new ();
	pj_a (s->pj);
	RShellCommand *sc = r_shell_fetch (s, cmd);

	while (sc) {
		RShellInstruction *si = r_shell_decode (s, sc);
		if (!si) {
			break;
		}
		pj_o (s->pj);
		pj_ks (s->pj, "command", sc->cmd);
		pj_ks (s->pj, "comment", sc->comment);
		pj_ks (s->pj, "atstr", si->atstr);
		pj_kn (s->pj, "repeat", si->repeat);
		pj_ka (s->pj, "args");
		RListIter *iter;
		char *arg;
		r_list_foreach (si->args, iter, arg) {
			pj_s (s->pj, arg);
		}
		pj_end (s->pj);
		pj_ka (s->pj, "ats");
		r_list_foreach (si->ats, iter, arg) {
			pj_s (s->pj, arg);
		}
		pj_end (s->pj);
		//
		pj_ka (s->pj, "fors");
		r_list_foreach (si->fors, iter, arg) {
			pj_s (s->pj, arg);
		}
		pj_end (s->pj);
		//
		pj_ka (s->pj, "trifors");
		r_list_foreach (si->trifors, iter, arg) {
			pj_s (s->pj, arg);
		}
		pj_end (s->pj);
		pj_ka (s->pj, "run");
		// one decoded instruction may require many evaluations to reach the final form
		for (;;) {
			pj_o (s->pj);
			char *output = r_shell_execute (s, si);
			if (output) {
				pj_ks (s->pj, "output", output);
			}
			pj_end (s->pj);
			if (!output) {
				continue;
			}
			// eprintf ("%s%c", output, 10);
			free (output);
			break;
		}
		pj_end (s->pj);
		r_shell_instruction_free (si);
		// fetch the next command (separated by newlines or semicolons)
		pj_end (s->pj);
		sc = r_shell_fetch (s, NULL);
	}
	pj_end (s->pj);
	if (s->error) {
		eprintf ("Error: %s%c", s->error, 10);
		R_FREE (s->error);
	}
	if (s->pj) {
		char *json = pj_drain (s->pj);
		char *ij = r_print_json_indent (json, true, "  ", NULL);
		printf ("%s%c", ij, 10);
		free (ij);
		free (json);
	}
	//
}

int main(int argc, char **argv) {
	RShell *s = r_shell_new ();
	RCore *core = r_core_new ();
	if (argc > 1) {
		run_command (core, s, argv[1]);
	} else {
		// run_command (core, s, "3s+32;px 64;w \"he#lo; wo#ld\"");
		while (1) {
			const char *line = r_line_readline ();
			if (*line == 'q') {
				break;
			}
			run_command (core, s, line);
		}
	}
	r_core_free (core);
	r_shell_free (s);
}

