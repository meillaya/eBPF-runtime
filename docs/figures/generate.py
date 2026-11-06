#!/usr/bin/env python3
"""Generate the README figures as Excalidraw scenes.

The scenes follow the house drawing rules: white background, roughness 2,
hachure fills, one claim per figure, three columns at most, labels of six
words or fewer. Run this file from the repository root, then render each
scene with the Excalidraw CLI.
"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent

INK = "#1e1e1e"
MUTED = "#5c5f66"
ROLES = {
    "input": ("#1971c2", "#d0ebff"),
    "runtime": ("#9c36b5", "#f3d9fa"),
    "analysis": ("#f08c00", "#fff3bf"),
    "risk": ("#e03131", "#ffe3e3"),
    "neutral": ("#495057", "#f1f3f5"),
    "model": ("#0c8599", "#c5f6fa"),
}

WIDTH = 1520
HEIGHT = 940
MARGIN = 40
FONT_TITLE = 32
FONT_BODY = 22
FONT_NOTE = 18

_seed = 1000


def seed():
    global _seed
    _seed += 1
    return _seed


def base(element_type, x, y, width, height, stroke, fill):
    return {
        "id": f"{element_type}-{seed()}",
        "type": element_type,
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "angle": 0,
        "strokeColor": stroke,
        "backgroundColor": fill,
        "fillStyle": "hachure",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 2,
        "opacity": 100,
        "groupIds": [],
        "frameId": None,
        "roundness": None,
        "seed": seed(),
        "version": 1,
        "versionNonce": seed(),
        "isDeleted": False,
        "boundElements": None,
        "updated": 1,
        "link": None,
        "locked": False,
    }


def box(x, y, width, height, role, label, font=FONT_BODY):
    stroke, fill = ROLES[role]
    shape = base("rectangle", x, y, width, height, stroke, fill)
    shape["roundness"] = {"type": 3}
    text_id = f"text-{seed()}"
    shape["boundElements"] = [{"type": "text", "id": text_id}]

    lines = label.split("\n")
    text_height = len(lines) * font * 1.25
    text = base("text", x + 10, y + (height - text_height) / 2, width - 20, text_height, INK, "transparent")
    text.update(
        {
            "id": text_id,
            "text": label,
            "originalText": label,
            "fontSize": font,
            "fontFamily": 1,
            "textAlign": "center",
            "verticalAlign": "middle",
            "containerId": shape["id"],
            "lineHeight": 1.25,
            "baseline": int(font * 0.8),
        }
    )
    return [shape, text]


def text(x, y, width, height, value, font=FONT_NOTE, color=INK):
    element = base("text", x, y, width, height, color, "transparent")
    element.update(
        {
            "text": value,
            "originalText": value,
            "fontSize": font,
            "fontFamily": 1,
            "textAlign": "left",
            "verticalAlign": "top",
            "containerId": None,
            "lineHeight": 1.25,
            "baseline": int(font * 0.8),
        }
    )
    return element


def arrow(x1, y1, x2, y2, label=None, dashed=False):
    dx, dy = x2 - x1, y2 - y1
    element = base("arrow", min(x1, x2), min(y1, y2), abs(dx), abs(dy), MUTED, "transparent")
    element.update(
        {
            "roundness": {"type": 2},
            "points": [[0, 0], [dx, dy]],
            "lastCommittedPoint": None,
            "startBinding": None,
            "endBinding": None,
            "startArrowhead": None,
            "endArrowhead": "arrow",
            "elbowed": False,
            "strokeStyle": "dashed" if dashed else "solid",
        }
    )
    elements = [element]
    if label:
        mid_x = (x1 + x2) / 2
        mid_y = (y1 + y2) / 2
        label_width = max(60, len(label) * 11)
        if dx == 0:
            label_x = x1 + 10
            label_y = mid_y - 12
        else:
            label_x = mid_x - label_width / 2
            label_y = mid_y - 30
        elements.append(text(label_x, label_y, label_width, 24, label, FONT_NOTE, MUTED))
    return elements


def scene(title, elements, note=None):
    items = [text(MARGIN, 32, WIDTH - 2 * MARGIN, 44, title, FONT_TITLE)]
    if note:
        items.append(text(MARGIN, 82, WIDTH - 2 * MARGIN, 26, note, FONT_NOTE, MUTED))
    items.extend(elements)
    return {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": items,
        "appState": {"gridSize": None, "viewBackgroundColor": "#ffffff"},
        "files": {},
    }


def architecture():
    elements = []
    elements += box(70, 200, 320, 86, "input", "process sensor\nfork / exec / exit")
    elements += box(70, 330, 320, 86, "input", "file sensor\nopen / mutate")
    elements += box(520, 200, 180, 216, "runtime", "ring buffers\none per sensor")
    elements += box(790, 200, 230, 86, "runtime", "decoder\nABI to fields")
    elements += box(790, 330, 230, 86, "runtime", "process table\ntgid to executable")
    elements += box(790, 470, 230, 86, "analysis", "rule engine\nYAML conditions")
    elements += box(1130, 200, 300, 86, "neutral", "JSON lines\nstdout")
    elements += box(1130, 470, 300, 86, "risk", "alerts\nstderr")

    elements += arrow(390, 243, 520, 243, "records")
    elements += arrow(390, 373, 520, 373, "records")
    elements += arrow(700, 243, 790, 243, "decode")
    elements += arrow(905, 286, 905, 330, "enrich")
    elements += arrow(905, 416, 905, 470, "fields")
    elements += arrow(1020, 243, 1130, 243, "write")
    elements += arrow(1020, 513, 1130, 513, "match")

    elements.append(text(MARGIN, 660, 700, 80, "check prints the same attach matrix\nwithout reading events.", FONT_NOTE, MUTED))
    elements.append(text(MARGIN, 760, 900, 80, "Measured on Linux 7.2.7 x86_64: process 3 programs, file 6.\nThe check command prints the same counts.", FONT_NOTE, MUTED))
    return scene("One node: kernel hooks to JSON lines", elements)


def event_path():
    elements = []
    y = 240
    elements += box(40, y, 210, 100, "input", "execve\n/bin/true")
    elements += box(350, y, 210, 100, "input", "raw tracepoint\nsched_process_exec", 20)
    elements += box(660, y, 210, 100, "input", "bprm->filename\n256 bytes")
    elements += box(970, y, 210, 100, "neutral", "ring record\n364 bytes")
    elements += box(1280, y, 210, 100, "runtime", "decoder\npath + pid + time")

    elements += arrow(250, 290, 350, 290, "call")
    elements += arrow(560, 290, 660, 290, "fire")
    elements += arrow(870, 290, 970, 290, "copy")
    elements += arrow(1180, 290, 1280, 290, "submit")

    elements += box(1280, 460, 210, 100, "neutral", 'JSON line\n"kind":"ProcessExec"')
    elements += arrow(1385, 340, 1385, 460, "parse")

    elements.append(text(40, 430, 900, 80, "Header 96 bytes, exec payload 268 bytes, no argv bytes.\nThe path is read from the kernel, then copied into the record.", FONT_NOTE, MUTED))
    elements.append(text(40, 560, 900, 80, "Measured record length: 364 bytes.\nargv is empty on the raw tracepoint path.", FONT_NOTE, MUTED))
    return scene("One exec event, end to end", elements)


def build_path():
    elements = []
    y = 240
    elements += box(30, y, 220, 100, "input", "C sensor source\nbpf/sensors/*.bpf.c", 20)
    elements += box(340, y, 220, 100, "input", "clang 19\ntarget bpf")
    elements += box(650, y, 220, 100, "neutral", "CO-RE object\nrelocations kept")
    elements += box(960, y, 220, 100, "runtime", "embedded bytes\ninclude_bytes!")
    elements += box(1270, y, 220, 100, "runtime", "loader\nopen + load")

    elements += arrow(250, 290, 340, 290, "compile")
    elements += arrow(560, 290, 650, 290, "emit")
    elements += arrow(870, 290, 960, 290, "embed")
    elements += arrow(1180, 290, 1270, 290, "start")

    elements.append(text(30, 430, 1100, 80, "Build time: clang 19 and the host BTF produce the object.\nRun time: libbpf relocates it against the running kernel.", FONT_NOTE, MUTED))
    elements.append(text(30, 560, 1200, 80, "clang 20 and newer are rejected: their memcpy extern does not\nresolve against the kernel BTF on the tested kernels.", FONT_NOTE, MUTED))
    return scene("Build path: C source to embedded object", elements)


def write(name, document):
    path = OUT / f"{name}.excalidraw"
    path.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {path}")


def main():
    write("runtime-architecture", architecture())
    write("exec-event-path", event_path())
    write("build-path", build_path())


if __name__ == "__main__":
    main()
