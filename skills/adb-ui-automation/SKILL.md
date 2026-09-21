---
name: adb-ui-automation
description: "Use when you need to interact with an Android app's UI (login, signup, buttons) without touching the screen, to automate flows or verify exploits via ADB uiautomator and input commands. Triggers - \"uiautomator\", \"adb input\", \"automate UI\", \"tap coordinates\", \"ui dump\""
platform: [android]
stack: [native]
category: enabling
kind: enabling
tier: A
related: []
---

# Skill: Android UI automation with ADB (uiautomator + input)

## When to use
You need to interact with an app's UI (login, signup, buttons) without touching the screen, to test flows or verify exploits.

## 1. Dump the UI hierarchy
```bash
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml
```
Extract useful info:
```bash
# Visible texts
adb shell cat /sdcard/ui.xml | grep -oE 'text="[^"]*"' | grep -v 'text=""'
# Bounds of an element by resource-id
adb shell cat /sdcard/ui.xml | grep -oE 'resource-id="<pkg>:id/<id>"[^>]*bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"'
```

## 2. Tap on coordinates
Bounds `[x1,y1][x2,y2]` → center = `((x1+x2)/2, (y1+y2)/2)`.
```bash
adb shell input tap 540 890
```

## 3. Type text
```bash
adb shell input text 'testuser'          # no spaces
adb shell input keyevent KEYCODE_MOVE_END
adb shell input keyevent 67              # DEL (repeat to delete)
```
Note: `input text` does not support spaces or special characters; use `%s` for a space.

## 4. Navigation
```bash
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_ENTER
adb shell am start -n <pkg>/.<Activity>
```

## 5. State verification
```bash
adb shell "dumpsys activity activities | grep mResumedActivity"
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png .
```

## 6. Common mistakes
- The tap does not register if the soft keyboard covers the button: close the keyboard with KEYCODE_BACK first.
- `input text` types into the focused field: check `focused="true"` in the dump.
- Bounds change with rotation/density: always re-dump before each interaction.
