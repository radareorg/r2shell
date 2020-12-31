/* radare2 - LGPL - Copyright 2020 - pancake */

#include <r_core.h>
#include <r_util.h>
#include "r_shell.h"

#define handle_skip(s, in) \
	if (*in == '\\') { escape = true;\
	} else if (*in == skip && !escape) { skip = 0;\
	} else { escape = false; }

R_API RShell *r_shell_new(void) {
	RShell *s = R_NEW0 (RShell);
	s->cmds = ht_pp_new0 ();
	return s;
}

R_API void r_shell_free(RShell *s) {
	r_list_free (s->stack);
	free (s->error);
	free (s);
}

R_API void r_shell_instruction_free(RShellInstruction *si) {
	r_list_free (si->args);
	r_list_free (si->ats);
	r_list_free (si->fors);
	r_list_free (si->trifors);
	free (si->_argstr);
	free (si);
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

R_API void r_shell_register(RShell *s, RShellHandler *sh) {
	ht_pp_insert (s->cmds, sh->cmd, sh);
}

static RList *shell_parse_split(RShell *s, const char *_cmd) {
	size_t nest = 0;
	const char *comment = NULL;
	char *pcmd = strdup (_cmd);
	char *cmd = pcmd;
	RList *stack = r_list_newf ((RListFree)r_shell_command_free);
	char *ocmd = cmd;
	int skip = 0;
	bool escape = false;
	while (*cmd) {
		if (skip) {
			if (nest) {
				if (!strncmp (cmd, "$(", 2)) {
					nest++;
					cmd++;
				} else if (*cmd == ')') {
					skip = 0;
				}
			}
			handle_skip (s, cmd);
			cmd++;
			continue;
		}
		escape = false;
		switch (*cmd) {
		case '$':
			if (cmd[1] == '(') {
				nest++;
				skip = true;
				// walk until ')' and increase nesting if '$(' is found again
			}
			break;
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
	RShellCommand *c = r_shell_command_new (ocmd);
	if (c) {
		if (comment) {
			c->comment = strdup (comment);
		}
		r_list_append (stack, c);
	}
	free (pcmd);
	return stack;
}

static void shell_split_args(RShellInstruction *si, const char *in) {
	const char *oin = in;
	bool escape = false;
	const char *ats = NULL;
	RList *args = si->args;
	int skip = 0;
	int nest = 0;
	while (*in) {
		if (skip) {
			if (nest) {
				if (!strncmp (in, "$(", 2)) {
					nest++;
				} else if (*in == ')') {
					nest--;
					if (nest < 1) {
						skip = false;
					}
				}
			} else {
				handle_skip (s, in);
			}
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
		case '$':
			if (in[1] == '(') {
				nest++;
				skip = ')';
			}
			break;
		case '`':
		case '\'':
		case '"':
			skip = *in;
			break;
		case '>':
			si->dumpstr = r_str_trim_dup (in + 1);
			goto done;
		case '|':
			si->pipestr = r_str_trim_dup (in + 1);
			goto done;
		case ' ':
			if (si->args == args) {
				char *a = r_str_ndup (oin, in - oin);
				r_str_trim (a);
				if (!R_STR_ISEMPTY (a)) {
					r_list_append (args, a);
				} else {
					free (a);
				}
				oin = in + 1;
			}
			break;
		}
		in++;
	}
done:
	if (*oin) {
		char *a = r_str_ndup (oin, in - oin);
		if (!R_STR_ISEMPTY (a)) {
			r_str_trim (a);
			r_list_append (args, a);
		} else {
			free (a);
		}
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
	if (si->repeat < 0) {
		si->repeat = 0;
	}
	si->_argstr = strdup (p);
	char *q = strdup (p);
	free (sc->cmd);
	sc->cmd = q;
	si->args = r_list_newf (free);
	si->ats = r_list_newf (free);
	si->fors = r_list_newf (free);
	si->trifors = r_list_newf (free);
	shell_split_args (si, si->_argstr);
	return si;
}

R_API RShellHandler *r_shell_find_handler(RShell *s, const char *cmd) {
	RShellHandler *sh = NULL;
	char *c = strdup (cmd);
	while (*c) {
		sh = ht_pp_find (s->cmds, c, NULL);
		if (sh) {
			break;
		}
		c[strlen (c) - 1] = 0;
	}
	free (c);
	return sh;
}

R_API void r_shell_result_free (RShellResult *sr) {
	free (sr->output);
	free (sr->error);
	free (sr);
}

R_API RShellResult* r_shell_result_new(char *output, char *error, int rc) {
	RShellResult *r = R_NEW (RShellResult);
	r->output = output;
	r->error = error;
	r->rc = rc;
	return r;
}

R_API RShellResult *r_shell_execute(RShell *s, RShellInstruction *si) {
	const char *cmd = r_list_get_n (si->args, 0);
	if (cmd) {
		RShellHandler *sh = r_shell_find_handler (s, cmd);
		if (sh) {
			eprintf ("FIND %p (%s)%c", sh, sh->cmd, 10);
			if (sh && sh->cb) {
				return sh->cb (s, si);
			}
			return r_shell_result_new (NULL, strdup ("Missing callback in handler."), 1);
		}
	}
	return r_shell_result_new (NULL, strdup ("Invalid command."), 1);
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

static bool r_shell_is_suffix(char ch) {
	switch (ch) {
	case 'j': // json
	case 'q': // quiet
	case '*': // r2
	case ',': // table
		return ch;
	}
	return 0;
}

static const char *find_expr(const char *a, const char **eof) {
	int nest = 0;
	const char *o = a;
	const char *p = a;
	while (*a) {
		if (!strncmp (a, "$(", 2)) {
			p = a + 2;
			nest++;
		} else if (*a == ')') {
			*eof = a;
			return p;
		}
		a++;
	}
	if (nest > 0) {
		eprintf ("Invalid nest.%c", 10);
	}
	return NULL;
}

static void shell_eval(RShell *s, RListIter *iter, const char *arg) {
	const char *a, *b;
	if (*arg == '"') {
		char *r = r_str_ndup (arg + 1, strlen (arg + 1) - 1);
		r_str_unescape (r);
		free (iter->data);
		iter->data = (void *)r;
		return;
	}
loop:
	for (a = arg; *a ; a++) {
		if (!strncmp (a, "$(", 2)) {
			const char *eof, *begin = find_expr (a, &eof);
			char *piece_a = r_str_ndup (arg, begin - arg - 2);
			char *piece_b = r_str_ndup (begin, eof - begin);
			char *piece_c = strdup (eof + 1);
			if (eof) {
				char *out = r_shell_fdex (s, piece_b);
				char *res = r_str_newf ("%s%s%s", piece_a, out, piece_c);
				free (iter->data);
				arg = res;
				iter->data = (void *)arg;
				free (out);
			}
			free (piece_a);
			free (piece_b);
			free (piece_c);
			goto loop;
		}
		if (*a == '`') {
			for (b = ++a; *b; b++) {
				if (*b == '`') {
					char *piece_a = r_str_ndup (arg, a - arg - 1);
					char *piece_b = r_str_ndup (a, b - a);
					char *piece_c = strdup (b + 1);
					char *out = r_shell_fdex (s, piece_b);
					char *res = r_str_newf ("%s%s%s", piece_a, out, piece_c);
					free (iter->data);
					arg = res;
					iter->data = (void *)arg;
					free (out);
					free (piece_a);
					free (piece_b);
					free (piece_c);
					goto loop;
				}
			}
		}
	}
	if (*a == '`') {
		eprintf ("Missing closing.%c", 10);
	}
}

static void instruction_suffix(RShellInstruction *si, const char *arg) {
	size_t arg_len = strlen (arg);
	if (arg_len > 1) {
		char ch = arg[arg_len - 1];
		if (r_shell_is_suffix (ch)) {
			si->suffix = ch;
		}
	}
}

R_API bool r_shell_eval(RShell *s, RShellInstruction *si);

R_API char *r_shell_fdex(RShell *s, const char *cmd) {
	RShellCommand *c = r_shell_fetch (s, cmd);
	if (c) {
		RShellInstruction *i = r_shell_decode (s, c);
		if (i) {
			r_shell_eval (s, i);
			RShellResult *sr = r_shell_execute (s, i);
			if (sr) {
				char *output = NULL;
				if (sr->output) {
					output = sr->output;
					sr->output = NULL;
				}
				if (sr->error) {
					eprintf ("%s\n", sr->error);
				}
				r_shell_result_free (sr);
				return output;
			}
		}
	}
	return NULL;
}


R_API bool r_shell_eval(RShell *s, RShellInstruction *si) {
	RListIter *iter;
	const char *arg;
	// evaluate all 
	r_list_foreach (si->args, iter, arg) {
		shell_eval (s, iter, arg);
	}
	char *arg0 = r_list_get_n (si->args, 0);
	if (!R_STR_ISEMPTY (arg0)) {
		instruction_suffix (si, arg0);
	}
	r_list_foreach (si->ats, iter, arg) {
		shell_eval (s, iter, arg);
	}
	r_list_foreach (si->fors, iter, arg) {
		shell_eval (s, iter, arg);
	}
	r_list_foreach (si->trifors, iter, arg) {
		shell_eval (s, iter, arg);
	}
	return true;
}

R_API void r_shell_json_from_instruction(PJ *pj, RShellInstruction *si) {
	RListIter *iter;
	char *arg;
	if (si->atstr) {
		pj_ks (pj, "atstr", si->atstr);
	}
	if (si->pipestr) {
		pj_ks (pj, "pipestr", si->pipestr);
	}
	if (si->dumpstr) {
		pj_ks (pj, "dumpstr", si->dumpstr);
	}
	pj_kn (pj, "repeat", si->repeat);
	pj_ka (pj, "args");
	r_list_foreach (si->args, iter, arg) {
		pj_s (pj, arg);
	}
	pj_end (pj);
	if (!r_list_empty (si->ats)) {
		pj_ka (pj, "ats");
		r_list_foreach (si->ats, iter, arg) {
			pj_s (pj, arg);
		}
		pj_end (pj);
	}
	if (!r_list_empty (si->fors)) {
		pj_ka (pj, "fors");
		r_list_foreach (si->fors, iter, arg) {
			pj_s (pj, arg);
		}
		pj_end (pj);
	}
	if (!r_list_empty (si->trifors)) {
		pj_ka (pj, "trifors");
		r_list_foreach (si->trifors, iter, arg) {
			pj_s (pj, arg);
		}
		pj_end (pj);
	}
}

static void run_command(RCore *core, RShell *s, const char *cmd) {
	// TODO: configure shell with proper syntax for command parsing
	RShellCommand *sc = r_shell_fetch (s, cmd);

	PJ *pj = s->pj = pj_new ();;
	pj_a (pj);
	while (sc) {
		RShellInstruction *si = r_shell_decode (s, sc);
		if (!si) {
			break;
		}
		pj_o (pj);
		pj_ks (pj, "command", sc->cmd);
		if (sc->comment) {
			pj_ks (pj, "comment", sc->comment);
		}
		r_shell_eval (s, si);
		r_shell_json_from_instruction (pj, si);
		RListIter *iter;
		char *arg;
		RShellResult *sr = r_shell_execute (s, si);
		pj_ka (pj, "result");
		if (sr->rc) {
			pj_kd (s->pj, "rc", sr->rc);
		}
		if (sr->error) {
			pj_ks (s->pj, "error", sr->output);
		}
		if (sr->output) {
			pj_ks (s->pj, "output", sr->output);
		}
		r_shell_result_free (sr);
		pj_end (s->pj);
		r_shell_instruction_free (si);
		pj_end (s->pj);
		// fetch the next command (separated by newlines or semicolons)
		sc = r_shell_fetch (s, NULL);
	}
	pj_end (s->pj);
	if (s->error) {
		eprintf ("Error: %s%c", s->error, 10);
		R_FREE (s->error);
	}
	{
		char *json = pj_drain (s->pj);
		char *ij = r_print_json_indent (json, true, "  ", NULL);
		printf ("%s%c", ij, 10);
		free (ij);
		free (json);
	}
}

RShellHandler *r_shell_handler_new(const char *cmd, RShellCallback cb) {
	RShellHandler *sh = R_NEW0 (RShellHandler);
	sh->cmd = strdup (cmd);
	sh->cb = cb;
	return sh;
}

static RShellResult *cmd_px(RShell *s, RShellInstruction *si) {
	return r_shell_result_new (strdup ("hexdump"), NULL, 0);
}

int main(int argc, char **argv) {
	RShell *s = r_shell_new ();

	r_shell_register (s, r_shell_handler_new ("px", &cmd_px));

	RCore *core = r_core_new ();
	if (argc > 1) {
		run_command (core, s, argv[1]);
	} else {
		// run_command (core, s, "3s+32;px 64;w \"he#lo; wo#ld\"");
		for (;;) {
			const char *line = r_line_readline ();
			if (!line || *line == 'q') {
				break;
			}
			run_command (core, s, line);
		}
	}
	r_core_free (core);
	r_shell_free (s);
}

