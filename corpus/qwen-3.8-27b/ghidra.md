

```bash
analyzeHeadless /path/to/project myProject \
  -import /path/to/binary \
  -postScript MyPostScript.py \
  -scriptPath /path/to/scripts \
  -writeProject
```

If the project may already exist and you want to overwrite it:

```bash
analyzeHeadless /path/to/project myProject \
  -overwriteProject \
  -import /path/to/binary \
  -postScript MyPostScript.py \
  -scriptPath /path/to/scripts \
  -writeProject
```