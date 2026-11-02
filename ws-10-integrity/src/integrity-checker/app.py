import copy
import json
import textwrap
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from flows import FlowCanvas, build_flow_graph
from integrity import KINDS, category, evidence_warnings, inventory, load_manifest, read_json, verify_dummy


HERE = Path(__file__).resolve().parent
COLORS = {"background": "#f6f7f9", "surface": "#ffffff", "ink": "#242b32",
          "muted": "#727b86", "green": "#23634f", "line": "#e2e6eb",
          "red": "#ad4056", "amber": "#916b27", "hover": "#edf1f5"}


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=True)


class Application(ctk.CTk):
    def __init__(self, manifest_path=HERE / "manifest.json"):
        ctk.set_appearance_mode("light")
        super().__init__()
        self.title("Integrity Checker")
        self.geometry("1080x780")
        self.minsize(820, 620)
        self.configure(fg_color=COLORS["background"])
        self.manifest_path = Path(manifest_path)
        self.manifest = load_manifest(self.manifest_path)
        self.records = inventory(self.manifest["baseline"])
        self.results = []
        self.candidate = None
        self.candidate_name = ""
        self.selected_kind = None
        self.search = ctk.StringVar()
        self._layout()
        self.search.trace_add("write", lambda *_: self._filter_artifacts())

    def _label(self, parent, text="", size=13, bold=False, muted=False, **options):
        return ctk.CTkLabel(parent, text=text, font=("Aptos", size, "bold" if bold else "normal"),
                            text_color=COLORS["muted"] if muted else COLORS["ink"], **options)

    def _button(self, parent, text, command, primary=False, **options):
        return ctk.CTkButton(parent, text=text, command=command, height=36, corner_radius=6,
                             font=("Aptos", 13), fg_color=COLORS["green"] if primary else COLORS["surface"],
                             text_color="white" if primary else COLORS["ink"],
                             hover_color="#194d3d" if primary else COLORS["hover"], **options)

    def _layout(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 24))
        header.grid_columnconfigure(0, weight=1)
        self._label(header, "Integrity Checker", size=21, bold=True).grid(row=0, column=0, sticky="w")
        self.navigation = ctk.CTkSegmentedButton(
            header, values=["Artifacts", "Verify AIBOM", "Flows"], command=self.show_page, height=36,
            font=("Aptos", 13), corner_radius=6, fg_color=COLORS["line"],
            selected_color=COLORS["surface"], selected_hover_color=COLORS["surface"],
            unselected_color=COLORS["line"], unselected_hover_color=COLORS["hover"], text_color=COLORS["ink"])
        self.navigation.grid(row=0, column=1, padx=(20, 18))
        self.reference_menu = ctk.CTkOptionMenu(
            header, values=["Open manifest...", "Save example..."], command=self._reference_action,
            width=125, height=36, corner_radius=6, font=("Aptos", 13),
            fg_color=COLORS["background"], button_color=COLORS["background"],
            button_hover_color=COLORS["hover"], text_color=COLORS["muted"],
            dropdown_fg_color=COLORS["surface"], dropdown_text_color=COLORS["ink"],
            dropdown_hover_color=COLORS["hover"])
        self.reference_menu.set("Reference")
        self.reference_menu.grid(row=0, column=2)
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=28)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.browser = ctk.CTkFrame(content, fg_color="transparent")
        self.verification = ctk.CTkFrame(content, fg_color="transparent")
        self.flows = ctk.CTkFrame(content, fg_color="transparent")
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=28, pady=(14, 16))
        self.reference_label = self._label(footer, muted=True, size=12)
        self.reference_label.pack(side="left")
        self._label(footer, "Dummy hashes", muted=True, size=12).pack(side="right")
        self._verification_page()
        self._flow_page()
        self._reference_label()
        self.show_cards()
        self.show_page("Artifacts")

    def show_page(self, page):
        self._evidence_tooltip()
        self.navigation.set(page)
        pages = {"Artifacts": self.browser, "Verify AIBOM": self.verification, "Flows": self.flows}
        for frame in pages.values():
            frame.grid_remove()
        pages[page].grid(row=0, column=0, sticky="nsew")

    def _reference_action(self, action):
        self.reference_menu.set("Reference")
        if action == "Open manifest...":
            self.open_manifest()
        else:
            self.save_baseline()

    def _reference_label(self):
        self.reference_label.configure(text=f"{self.manifest.get('release', 'Reference')}  |  "
                                            f"{len(self.records)} artifacts  |  {self.manifest_path.name}")

    def _text_area(self, parent):
        return ctk.CTkTextbox(parent, wrap="word", font=("Cascadia Code", 12),
                              fg_color=COLORS["surface"], text_color=COLORS["ink"],
                              corner_radius=6, border_spacing=16, state="disabled")

    def _set_text(self, widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _evidence_tooltip(self, event=None):
        if hasattr(self, "evidence_tooltip"):
            self.evidence_tooltip.place_forget()
        if event is None:
            return
        if not hasattr(self, "evidence_tooltip"):
            self.evidence_tooltip = tk.Label(
                self, text="Evidence requirements unmet\nSelect artifact for details",
                font=("Aptos", 11), background="#fff0cc", foreground=COLORS["amber"],
                padx=8, pady=5, relief="solid", borderwidth=1)
        self.evidence_tooltip.update_idletasks()
        left = max(0, min(event.x_root - self.winfo_rootx() + 12,
                          self.winfo_width() - self.evidence_tooltip.winfo_reqwidth() - 8))
        top = max(0, min(event.y_root - self.winfo_rooty() + 18,
                         self.winfo_height() - self.evidence_tooltip.winfo_reqheight() - 8))
        self.evidence_tooltip.place(x=left, y=top)
        self.evidence_tooltip.lift()

    def _evidence_badge(self, parent, command):
        badge = ctk.CTkLabel(parent, text="\u26a0", width=24, height=24,
                             font=("Segoe UI Symbol", 18), text_color=COLORS["amber"], cursor="hand2")
        badge.bind("<Enter>", self._evidence_tooltip)
        badge.bind("<Leave>", lambda event: self._evidence_tooltip())
        badge.bind("<Button-1>", lambda event: command())
        return badge

    def _evidence_details(self, ref):
        warnings = self.evidence_by_ref.get(ref, [])
        return ("Evidence warnings (declarations only; evidence not verified)\n" +
                "\n".join(f"- {warning}" for warning in warnings)) if warnings else ""

    def show_cards(self):
        self.selected_kind = None
        for child in self.browser.winfo_children():
            child.destroy()
        grid = ctk.CTkScrollableFrame(self.browser, fg_color="transparent", corner_radius=0)
        grid.pack(fill="both", expand=True)
        for column in range(3):
            grid.grid_columnconfigure(column, weight=1, uniform="cards")
        counts = Counter(category(record) for record in self.records.values())
        self.type_cards = {}
        for index, kind in enumerate(KINDS):
            count = counts[kind]
            card = ctk.CTkButton(
                grid, text=f"{kind}\n\n{count} artifact{'s' if count != 1 else ''}",
                command=lambda selected=kind: self.show_artifacts(selected),
                anchor="w", font=("Aptos", 15), height=116, width=190,
                corner_radius=8, border_width=1, border_color=COLORS["line"],
                fg_color=COLORS["surface"], text_color=COLORS["ink"], hover_color=COLORS["hover"])
            card.grid(row=index // 3, column=index % 3, sticky="ew", padx=6, pady=6)
            self.type_cards[kind] = card

    def show_artifacts(self, kind):
        self.selected_kind = kind
        for child in self.browser.winfo_children():
            child.destroy()
        toolbar = ctk.CTkFrame(self.browser, fg_color="transparent")
        toolbar.pack(fill="x", pady=(0, 14))
        self._button(toolbar, "< All types", self.show_cards, width=100).pack(side="left")
        self._label(toolbar, kind, size=17, bold=True).pack(side="left", padx=16)
        self.search_entry = ctk.CTkEntry(
            toolbar, placeholder_text="Search artifacts", width=210, height=36, corner_radius=6,
            font=("Aptos", 13), fg_color=COLORS["surface"], border_color=COLORS["line"],
            text_color=COLORS["ink"])
        self.search_entry.pack(side="right")
        self.search_entry.bind("<KeyRelease>", lambda event: self.search.set(self.search_entry.get()))
        split = ctk.CTkFrame(self.browser, fg_color="transparent")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(1, weight=1)
        split.grid_rowconfigure(0, weight=1)
        self.artifact_list = ctk.CTkScrollableFrame(split, width=235, fg_color="transparent", corner_radius=0)
        self.artifact_list.grid(row=0, column=0, sticky="ns", padx=(0, 16))
        self.artifact_list.grid_columnconfigure(0, weight=1)
        self.artifact_detail = self._text_area(split)
        self.artifact_detail.grid(row=0, column=1, sticky="nsew")
        self.search.set("")

    def _filter_artifacts(self):
        if self.selected_kind is None:
            return
        for child in self.artifact_list.winfo_children():
            child.destroy()
        self.artifact_buttons = {}
        self.artifact_badges = {}
        needle = self.search.get().casefold()
        for ref, record in sorted(self.records.items(), key=lambda item: item[1].get("name", "")):
            if category(record) == self.selected_kind and needle in f"{ref} {record.get('name', '')}".casefold():
                name = textwrap.shorten(record.get("name", ref), width=25, placeholder="...")
                button = ctk.CTkButton(
                    self.artifact_list, text=f"{name}\nv{record.get('version', '-')}",
                    command=lambda selected=ref: self._select_artifact(selected), height=64, width=190,
                    anchor="w", font=("Aptos", 13), corner_radius=6, fg_color=COLORS["surface"],
                    text_color=COLORS["ink"], hover_color=COLORS["hover"])
                button.grid(row=len(self.artifact_buttons), column=0, sticky="ew", pady=(0, 6))
                if self.evidence_by_ref.get(ref):
                    badge = self._evidence_badge(self.artifact_list, lambda selected=ref: self._select_artifact(selected))
                    badge.grid(row=len(self.artifact_buttons), column=1, padx=(4, 0), pady=(0, 6))
                    self.artifact_badges[ref] = badge
                self.artifact_buttons[ref] = button
        if self.artifact_buttons:
            self._select_artifact(next(iter(self.artifact_buttons)))
        else:
            self._set_text(self.artifact_detail, "No artifacts found.")

    def _select_artifact(self, ref):
        for item_ref, button in self.artifact_buttons.items():
            button.configure(fg_color=COLORS["hover"] if item_ref == ref else COLORS["surface"])
        dependencies = next((item.get("dependsOn", []) for item in self.manifest["baseline"].get("dependencies", [])
                             if item["ref"] == ref), [])
        dependents = [item["ref"] for item in self.manifest["baseline"].get("dependencies", [])
                      if ref in item.get("dependsOn", [])]
        self._set_text(self.artifact_detail, self._evidence_details(ref) + "\n\n" + json_text({
            "artifact": self.records[ref], "artifactPath": self.manifest.get("artifactPaths", {}).get(ref),
            "dependsOn": dependencies, "usedBy": dependents,
        }))

    def _verification_page(self):
        controls = ctk.CTkFrame(self.verification, fg_color="transparent")
        controls.pack(fill="x")
        self._button(controls, "Open AIBOM", self.open_aibom, primary=True, width=130).pack(side="left")
        self.sample_menu = ctk.CTkOptionMenu(
            controls, values=["Matching sample", "Modified sample"], command=self._sample_action,
            width=145, height=36, corner_radius=6, font=("Aptos", 13),
            fg_color=COLORS["background"], button_color=COLORS["background"],
            button_hover_color=COLORS["hover"], text_color=COLORS["muted"],
            dropdown_fg_color=COLORS["surface"], dropdown_text_color=COLORS["ink"],
            dropdown_hover_color=COLORS["hover"])
        self.sample_menu.set("Samples")
        self.sample_menu.pack(side="left", padx=10)
        self.source_label = self._label(self.verification, "No AIBOM selected", muted=True, anchor="w")
        self.source_label.pack(fill="x", pady=(16, 2))
        self.source_label.bind("<Configure>", lambda event: self.source_label.configure(wraplength=max(100, event.width - 12)))
        self.summary = self._label(self.verification, "", size=18, bold=True, anchor="w")
        self.summary.pack(fill="x", pady=(0, 16))
        self.result_list = ctk.CTkScrollableFrame(self.verification, fg_color="transparent", corner_radius=0)
        self.result_list.pack(fill="both", expand=True)
        self.result_list.grid_columnconfigure(0, weight=1)
        self.result_detail = self._text_area(self.verification)
        self.result_detail.configure(height=130)
        self.result_rows = []
        self.result_badges = {}

    def _sample_action(self, sample):
        self.sample_menu.set("Samples")
        self.flow_samples.set("Samples")
        self.load_sample(modified=sample == "Modified sample")

    def _flow_page(self):
        controls = ctk.CTkFrame(self.flows, fg_color="transparent")
        controls.pack(fill="x")
        self._button(controls, "Open AIBOM", self.open_aibom, primary=True, width=130).pack(side="left")
        self.flow_samples = ctk.CTkOptionMenu(
            controls, values=["Matching sample", "Modified sample"], command=self._sample_action,
            width=145, height=36, corner_radius=6, font=("Aptos", 13),
            fg_color=COLORS["background"], button_color=COLORS["background"],
            button_hover_color=COLORS["hover"], text_color=COLORS["muted"],
            dropdown_fg_color=COLORS["surface"], dropdown_text_color=COLORS["ink"],
            dropdown_hover_color=COLORS["hover"])
        self.flow_samples.set("Samples")
        self.flow_samples.pack(side="left", padx=10)
        self._button(controls, "Fit", lambda: self.flow_canvas.fit(), width=42).pack(side="right")
        self._button(controls, "+", lambda: self.flow_canvas.zoom(1.2), width=34).pack(side="right", padx=6)
        self._button(controls, "-", lambda: self.flow_canvas.zoom(1 / 1.2), width=34).pack(side="right")
        information = ctk.CTkFrame(self.flows, fg_color="transparent")
        information.pack(fill="x", pady=(16, 12))
        information.grid_columnconfigure(0, weight=1)
        self.flow_source = self._label(information, muted=True, anchor="w", width=1)
        self.flow_source.grid(row=0, column=0, sticky="ew")
        self.flow_source.bind("<Configure>", lambda event: self.flow_source.configure(wraplength=max(100, event.width - 12)))
        legend = (("Matching", COLORS["green"]), ("At risk", "#a66c0a"), ("Unmatched", COLORS["red"]))
        for column, (text, color) in enumerate(legend, start=1):
            label = self._label(information, text, size=12)
            label.configure(text_color=color)
            label.grid(row=0, column=column, padx=(14, 0))
        self.flow_summary = self._label(self.flows, "Dependency -> consumer", muted=True, size=12, anchor="w")
        self.flow_summary.pack(fill="x", pady=(0, 8))
        self.flow_summary.bind("<Configure>", lambda event: self.flow_summary.configure(wraplength=max(100, event.width - 12)))
        self.flow_canvas = FlowCanvas(self.flows, self._select_flow_node)
        self.flow_canvas.pack(fill="both", expand=True)
        self.flow_detail = self._text_area(self.flows)
        self.flow_detail.configure(height=115)
        self._refresh_flows()

    def _refresh_flows(self):
        self._evidence_tooltip()
        self.flow_detail.pack_forget()
        source = self.candidate if self.candidate is not None else self.manifest["baseline"]
        records = inventory(source)
        self.evidence_by_ref = {ref: evidence_warnings(self.manifest, ref, records.get(ref))
                                for ref in self.records.keys() | records.keys()}
        self.flow_source.configure(text=Path(self.candidate_name).name if self.candidate is not None else "Reference preview")
        try:
            graph = build_flow_graph(source, self.results)
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            self.flow_canvas.set_graph(None)
            self.flow_summary.configure(text=f"Invalid dependencies: {error}")
            return
        for ref, node in graph.nodes(data=True):
            node["evidenceWarnings"] = self.evidence_by_ref.get(ref, [])
        self.flow_canvas.set_graph(graph)
        self.flow_canvas.canvas.tag_bind("evidence-warning", "<Enter>", self._evidence_tooltip)
        self.flow_canvas.canvas.tag_bind("evidence-warning", "<Leave>", lambda event: self._evidence_tooltip())
        self.flow_summary.configure(text=f"Dependency -> consumer  |  {len(graph)} artifacts  |  {graph.number_of_edges()} links")
        if self.selected_kind is not None:
            self._filter_artifacts()

    def _select_flow_node(self, ref, node):
        causes = ", ".join(node.get("untrustedDependencies", [])) or "-"
        self._set_text(self.flow_detail, f"{node['name']}  /  {ref}  /  {node['status']}\n"
                   f"Untrusted dependencies  {causes}\n"
                   f"Hash      {node.get('hashStatus', node['status'])}\n\n"
                       f"Manifest  {node.get('expectedHash') or '-'}\n"
                   f"AIBOM     {node.get('submittedHash') or '-'}\n\n" + self._evidence_details(ref))
        self.flow_detail.pack(fill="x", pady=(12, 0))

    def open_manifest(self):
        path = filedialog.askopenfilename(title="Open reference manifest", filetypes=[("JSON manifest", "*.json")])
        if not path:
            return
        try:
            manifest = load_manifest(path)
            records = inventory(manifest["baseline"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
            messagebox.showerror("Manifest not loaded", str(error))
            return
        self.manifest_path = Path(path)
        self.manifest = manifest
        self.records = records
        self.candidate = None
        self.source_label.configure(text="No AIBOM selected")
        self._clear_results()
        self._reference_label()
        self.show_cards()

    def _clear_results(self):
        self.results = []
        self.summary.configure(text="")
        for child in self.result_list.winfo_children():
            child.destroy()
        self.result_rows = []
        self._set_text(self.result_detail, "")
        self.result_badges = {}
        self.result_detail.pack_forget()
        self._refresh_flows()

    def open_aibom(self):
        path = filedialog.askopenfilename(title="Open CycloneDX AIBOM", filetypes=[("CycloneDX JSON", "*.json")])
        if not path:
            return
        try:
            candidate = read_json(path)
            inventory(candidate)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
            messagebox.showerror("AIBOM not loaded", str(error))
            return
        self.candidate = candidate
        self.candidate_name = str(Path(path).resolve())
        self.source_label.configure(text=Path(path).name)
        self._clear_results()
        self.run_verification()

    def load_sample(self, modified=False):
        candidate = copy.deepcopy(self.manifest["baseline"])
        if modified:
            target = next((item for item in inventory(candidate).values()
                           if any(entry.get("alg") == "SHA-256" for entry in item.get("hashes", []))), None)
            if target is None:
                messagebox.showerror("Sample unavailable", "This manifest has no artifact hashes.")
                return
            entry = next(entry for entry in target["hashes"] if entry.get("alg") == "SHA-256")
            entry["content"] = "0" * 64 if entry["content"] != "0" * 64 else "f" * 64
        self.candidate = candidate
        self.candidate_name = "Modified sample" if modified else "Matching sample"
        self.source_label.configure(text=self.candidate_name)
        self._clear_results()
        self.run_verification()

    def run_verification(self):
        if self.candidate is None:
            return
        self._clear_results()
        try:
            self.results = verify_dummy(self.manifest, self.candidate)
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as error:
            self.summary.configure(text="Could not compare hashes")
            messagebox.showerror("Invalid AIBOM", str(error))
            return
        counts = Counter(row["status"] for row in self.results)
        self.summary.configure(text=f"{counts['MATCH']} match  /  {len(self.results) - counts['MATCH']} need attention")
        self._render_results()
        self._refresh_flows()

    def _render_results(self):
        for child in self.result_list.winfo_children():
            child.destroy()
        self.result_rows = []
        self.result_badges = {}
        for index, row in enumerate(self.results):
            frame = ctk.CTkFrame(self.result_list, fg_color=COLORS["surface"], corner_radius=6, height=44,
                                 cursor="hand2")
            frame.grid(row=index, column=0, sticky="ew", pady=(0, 5))
            frame.grid_columnconfigure(0, weight=1)
            name = self._label(frame, textwrap.shorten(row["name"], width=65, placeholder="..."), anchor="w")
            name.grid(row=0, column=0, sticky="ew", padx=14, pady=8)
            color = COLORS["green"] if row["status"] == "MATCH" else (
                COLORS["amber"] if row["status"] == "NO HASH" else COLORS["red"])
            status = self._label(frame, row["status"], size=12, bold=True, width=105, anchor="e")
            status.configure(text_color=color)
            status.grid(row=0, column=2, padx=14, pady=8)
            if row.get("evidenceWarnings"):
                badge = self._evidence_badge(frame, lambda selected=index: self._select_result(selected))
                badge.grid(row=0, column=1, padx=(4, 0), pady=8)
                self.result_badges[row["ref"]] = badge
            for widget in (frame, name, status):
                widget.bind("<Button-1>", lambda event, selected=index: self._select_result(selected))
            self.result_rows.append(frame)

    def _select_result(self, index):
        for number, frame in enumerate(self.result_rows):
            frame.configure(fg_color=COLORS["hover"] if number == index else COLORS["surface"])
        row = self.results[index]
        self._set_text(self.result_detail, f"{row['name']}  /  {row['ref']}\n\n"
                       f"Manifest  {row['expectedHash'] or '-'}\n"
                       f"AIBOM     {row['submittedHash'] or '-'}\n\n" + self._evidence_details(row["ref"]))
        self.result_detail.pack(fill="x", pady=(12, 0))

    def save_baseline(self):
        self._save_json("reference.cdx.json", self.manifest["baseline"])

    def _save_json(self, name, value):
        path = filedialog.asksaveasfilename(initialfile=name, defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            try:
                destination = Path(path).resolve()
                protected = {self.manifest_path.resolve()}
                protected.update((self.manifest_path.parent / relative).resolve()
                                 for relative in self.manifest.get("artifactPaths", {}).values())
                if destination in protected:
                    raise ValueError("Cannot overwrite the reference manifest or its artifact files.")
                destination.write_text(json_text(value) + "\n", encoding="utf-8")
            except (OSError, ValueError) as error:
                messagebox.showerror("Could not save", str(error))


if __name__ == "__main__":
    try:
        app = Application()
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        messagebox.showerror("Startup failed", str(error))
    else:
        app.mainloop()