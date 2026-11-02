import tkinter as tk
from tkinter import font as tkfont

import customtkinter as ctk
import networkx as nx

from integrity import inventory


def build_flow_graph(bom, results=()):
    records = inventory(bom)
    statuses = {row["ref"]: row for row in results}
    graph = nx.DiGraph()
    for ref in sorted(records.keys() | statuses.keys()):
        record = records.get(ref, {})
        result = statuses.get(ref, {})
        graph.add_node(ref, name=record.get("name", result.get("name", ref)),
                       status=result.get("status", "NOT CHECKED"),
                       expectedHash=result.get("expectedHash"), submittedHash=result.get("submittedHash"))
    dependencies = bom.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be an array.")
    for entry in dependencies:
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str) or not entry["ref"]:
            raise ValueError("Every dependency record needs a nonempty ref.")
        targets = entry.get("dependsOn", [])
        if not isinstance(targets, list) or any(not isinstance(ref, str) or not ref for ref in targets):
            raise ValueError("dependsOn must contain nonempty artifact references.")
        for ref in [entry["ref"], *targets]:
            if ref not in graph:
                graph.add_node(ref, name=ref, status="UNRESOLVED", expectedHash=None, submittedHash=None)
        for dependency in targets:
            graph.add_edge(dependency, entry["ref"])
    for _, node in graph.nodes(data=True):
        node["hashStatus"] = node["status"]
        node["untrustedDependencies"] = []
    untrusted = sorted(ref for ref, node in graph.nodes(data=True)
                       if node["hashStatus"] not in ("MATCH", "NOT CHECKED"))
    for source in untrusted:
        for consumer in nx.descendants(graph, source):
            node = graph.nodes[consumer]
            node["untrustedDependencies"].append(source)
            if node["hashStatus"] == "MATCH":
                node["status"] = "AT RISK"
    return graph


def flow_positions(graph):
    if not graph:
        return {}
    positions = {}
    offset = 0
    for component in sorted(nx.weakly_connected_components(graph), key=lambda members: min(members)):
        condensed = nx.condensation(graph.subgraph(component))
        layers = []
        for generation in nx.topological_generations(condensed):
            members = [ref for group in generation for ref in condensed.nodes[group]["members"]]
            layers.append(sorted(members))
        height = max(len(layer) for layer in layers) * 112
        positions.update({ref: (140 + column * 270, 75 + offset + (height - len(layer) * 112) / 2 + row * 112)
                          for column, layer in enumerate(layers) for row, ref in enumerate(layer)})
        offset += height + 80
    return positions


class FlowCanvas(ctk.CTkFrame):
    def __init__(self, parent, on_select):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(self, background="#f6f7f9", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vertical = ctk.CTkScrollbar(self, command=self.canvas.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ctk.CTkScrollbar(self, orientation="horizontal", command=self.canvas.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.canvas.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.canvas.bind("<Configure>", lambda event: self.fit())
        self.canvas.bind("<ButtonPress-1>", lambda event: self.canvas.scan_mark(event.x, event.y))
        self.canvas.bind("<B1-Motion>", lambda event: self.canvas.scan_dragto(event.x, event.y, gain=1))
        self.canvas.bind("<MouseWheel>", lambda event: self.zoom(1.15 if event.delta > 0 else 1 / 1.15))
        self.canvas.bind("<Button-4>", lambda event: self.zoom(1.15))
        self.canvas.bind("<Button-5>", lambda event: self.zoom(1 / 1.15))
        self.on_select = on_select
        self.graph = None
        self.positions = {}
        self.node_items = {}
        self.warning_items = {}
        self.scale = 1

    def set_graph(self, graph):
        self.graph = graph
        self.positions = flow_positions(graph)
        self.fit()

    def fit(self):
        if self.positions:
            width = max(position[0] for position in self.positions.values()) - min(position[0] for position in self.positions.values()) + 250
            height = max(position[1] for position in self.positions.values()) - min(position[1] for position in self.positions.values()) + 110
            self.scale = max(0.35, min(1.25, (self.canvas.winfo_width() - 40) / width,
                                       (self.canvas.winfo_height() - 40) / height))
        self._draw_graph()
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)

    def zoom(self, factor):
        self.scale = max(0.35, min(2.5, self.scale * factor))
        self._draw_graph()

    def _draw_graph(self):
        self.canvas.delete("all")
        self.node_items = {}
        self.warning_items = {}
        if not self.positions:
            self.canvas.configure(scrollregion=(0, 0, 1, 1))
            return
        scale = self.scale
        minimum_x = min(position[0] for position in self.positions.values())
        minimum_y = min(position[1] for position in self.positions.values())
        positions = {ref: ((position[0] - minimum_x + 125) * scale + 20,
                           (position[1] - minimum_y + 55) * scale + 20)
                     for ref, position in self.positions.items()}
        half_width, half_height = 105 * scale, max(19, 37 * scale)
        for source, target in self.graph.edges:
            source_x, source_y = positions[source]
            target_x, target_y = positions[target]
            delta_x, delta_y = target_x - source_x, target_y - source_y
            if source == target:
                points = (source_x + half_width, source_y, source_x + half_width + 28,
                          source_y - half_height - 28, source_x - half_width - 28,
                          source_y - half_height - 28, source_x - half_width, source_y)
            else:
                boundary = min(half_width / abs(delta_x) if delta_x else float("inf"),
                               half_height / abs(delta_y) if delta_y else float("inf"))
                points = (source_x + delta_x * boundary, source_y + delta_y * boundary,
                          target_x - delta_x * boundary, target_y - delta_y * boundary)
            self.canvas.create_line(*points, fill="#a3adb9", width=1.5, arrow=tk.LAST,
                                    arrowshape=(8, 10, 4), smooth=source == target, tags="edge")
        name_font = tkfont.Font(family="Aptos", size=-max(11, round(14 * scale)), weight="bold")
        status_font = tkfont.Font(family="Aptos", size=-max(9, round(11 * scale)))
        self._fonts = (name_font, status_font)
        for ref, (center_x, center_y) in positions.items():
            node = self.graph.nodes[ref]
            status = node["status"]
            fill, outline = {
                "MATCH": ("#e1f1e7", "#23634f"),
                "AT RISK": ("#fff0cc", "#a66c0a"),
                "NOT CHECKED": ("#edf0f4", "#727b86"),
            }.get(status, ("#fae5e9", "#ad4056"))
            tag = f"node-{len(self.node_items)}"
            rectangle = self.canvas.create_rectangle(center_x - half_width, center_y - half_height,
                                                      center_x + half_width, center_y + half_height,
                                                      fill=fill, outline=outline, width=1.5, tags=tag)
            name = str(node["name"])
            warning_width = 22 if node.get("evidenceWarnings") else 0
            while len(name) > 1 and name_font.measure(name) > half_width * 2 - 16 - warning_width:
                name = name[:-4] + "..." if name.endswith("...") else name[:-1] + "..."
            self.canvas.create_text(center_x - warning_width / 2, center_y - max(7, 10 * scale), text=name, font=name_font,
                                    fill="#242b32", tags=tag)
            if warning_width:
                warning = self.canvas.create_text(
                    center_x + half_width - 11, center_y - max(7, 10 * scale), text="\u26a0",
                    font=("Segoe UI Symbol", -max(12, round(16 * scale))),
                    fill="#916b27", tags=(tag, "evidence-warning"))
                self.warning_items[ref] = warning
            self.canvas.create_text(center_x, center_y + max(8, 14 * scale), text=status, font=status_font,
                                    fill=outline, tags=tag)
            self.canvas.tag_bind(tag, "<Button-1>", lambda event, selected=ref: self.on_select(selected, self.graph.nodes[selected]))
            self.canvas.tag_bind(tag, "<Enter>", lambda event: self.canvas.configure(cursor="hand2"))
            self.canvas.tag_bind(tag, "<Leave>", lambda event: self.canvas.configure(cursor=""))
            self.node_items[ref] = rectangle
        bounds = self.canvas.bbox("all")
        self.canvas.configure(scrollregion=(bounds[0] - 20, bounds[1] - 20, bounds[2] + 20, bounds[3] + 20))