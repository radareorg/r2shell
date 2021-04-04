typedef struct {
	char *cmd;
	char *comment;
} RShellCommand;

typedef struct {
	char *output;
	char *error;
	int rc;
	RShellUndo *undo;
} RShellResult;

typedef struct {
	int repeat;
	RList *args;
	RList *ats;
	RList *fors;
	RList *trifors;
	RShellCommand *sc;
	char suffix;
	char *_argstr;
	char *atstr;
	char *pipestr;
	char *dumpstr;
} RShellInstruction;

typedef bool (*RShellUndoCb)(void *user);
typedef void (*RShellUndoFreeCb)(void *user);

typedef struct r_shell_undo_t {
	RShellUndoCb cb;
	RShellUndoFreeCb free;
	void *user;
} RShellUndo;

typedef struct {
	// hold configuration and available commands
	RList *stack; // pile of pending commands to be fetched
	char *error;
	PJ *pj;
	HtPP *cmds;
	RList *undo;
	ut32 max_undo;
} RShell;

typedef RShellResult *(*RShellCallback)(RShell *s, RShellInstruction *si);

typedef struct {
	char *cmd;
	RShellCallback cb;
} RShellHandler;

R_API RShell *r_shell_new(void);
R_API void r_shell_free(RShell *s);
R_API void r_shell_instruction_free(RShellInstruction *si);
R_API RShellCommand *r_shell_command_new(const char *ocmd);
R_API void r_shell_command_free(RShellCommand *s);
R_API void r_shell_register(RShell *s, RShellHandler *sh);
R_API RShellInstruction *r_shell_decode(RShell *s, RShellCommand *sc);
R_API RShellHandler *r_shell_find_handler(RShell *s, const char *cmd);
R_API RShellResult* r_shell_result_new(char *output, char *error, int rc, RShellUndo *undo);
R_API RShellResult *r_shell_execute(RShell *s, RShellInstruction *si);
R_API RShellCommand *r_shell_fetch(RShell *s, const char *cmd);
R_API bool r_shell_eval(RShell *s, RShellInstruction *si);
R_API char *r_shell_fdex(RShell *s, const char *cmd);
R_API bool r_shell_eval(RShell *s, RShellInstruction *si);
R_API void r_shell_json_from_instruction(PJ *pj, RShellInstruction *si);
R_API RShellHandler *r_shell_handler_new(const char *cmd, RShellCallback cb);
R_API bool r_shell_undo(RShell *sh);

