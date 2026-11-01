Here is a typical `analyzeHeadless` command that imports a binary, runs analysis, executes a post-script, and saves the Ghidra project to a directory you specify.

### Linux / macOS

```bash
GHIDRA_DIR=/opt/ghidra_10.4

$GHIDRA_DIR/support/analyzeHeadless \
    -projectdir /path/to/your/project_directory \
    -projectname MyBinaryProject \
    -import /path/to/your/binary \
    -postScript /path/to/your/PostAnalysisScript.java \
    -overwrite
```

### Windows

```cmd
set GHIDRA_DIR=C:\ghidra_10.4

%GHIDRA_DIR%\support\analyzeHeadless.bat ^
    -projectdir C:\path\to\your\project_directory ^
    -projectname MyBinaryProject ^
    -import C:\path\to\your\binary ^
    -postScript C:\path\to\your\PostAnalysisScript.java ^
    -overwrite
```

---

### What the flags do

| Flag | Meaning |
|------|---------|
| `-projectdir <path>` | Directory where the Ghidra project (`.gpr` + repository) will be created. |
| `-projectname <name>` | Name of the Ghidra project. |
| `-import <binary>` | Imports and analyzes the target binary. |
| `-postScript <script>` | Runs the script **after** auto-analysis finishes. Can be a `.java` (Ghidra Java script) or `.py` (Python) script. |
| `-overwrite` | Replaces the project if one with the same name already exists in that directory. |

### Passing arguments to the post-script

Arguments placed after the script name are passed to the script:

```bash
    -postScript /path/to/PostAnalysisScript.java arg1 "arg with spaces"
```

Inside a Ghidra Java script, you can retrieve them with `getArgument()` / `getArguments()` (depending on your Ghidra version); in a Python script they are available via `getArguments()` or the script’s argument handling.

### Notes

* The project is written to disk automatically when `analyzeHeadless` exits (unless you use `-readOnly`).
* If you do **not** want to re-import the binary and instead run the script against an already-imported program in an existing project, omit `-import` and point `-projectdir`/`-projectname` at the existing project.
* For very large binaries you may need to increase the JVM heap, e.g. by setting `DEFAULT_JAVA_MEMORY=4g` before calling `analyzeHeadless`.