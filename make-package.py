#!/usr/bin/python3
import os
import shutil

OUT = "./out"

files = [
    "taskManager/forms.py",
    "taskManager/misc.py",
    "taskManager/settings.py",
    "taskManager/taskManager_urls.py",
    "taskManager/static/taskManager/js/",
    "taskManager/templates/",
    "taskManager/urls.py",
    "taskManager/views.py",
]


if os.path.exists(OUT):
    shutil.rmtree(OUT)

os.makedirs(OUT)
os.makedirs(os.path.join(OUT, "taskManager"))
os.makedirs(os.path.join(OUT, "taskManager/js"))


for f in files:
    print("copying", f)
    if f.endswith("/"):
        shutil.copytree(f, os.path.join(OUT, f))
    else:
        shutil.copy(f, os.path.join(OUT, f))


shutil.make_archive("appsec-submission", 'zip', OUT)

if os.path.exists(OUT):
    shutil.rmtree(OUT)
