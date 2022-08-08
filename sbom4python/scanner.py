# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import subprocess


class SBOMScanner:
    """
    Simple SBOM File Scanner.
    """

    def __init__(self, debug):
        self.record = []
        self.debug = debug

    def set_module(self, module):
        self.module = module
        self.module_valid = False
        if self.debug:
            print(f"Module: {self.module}")

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # Split command line into individual elements
        params = command_line.split()
        res = subprocess.run(params, capture_output=True, text=True)
        return res.stdout.splitlines()

    def process_module(self):
        out = self.run_program(f"pip show {self.module}")
        # If module not found, no metadata returned
        if len(out) > 0:
            self.metadata = {}
            self.module_valid = True
            for line in out:
                entry = line.split(":")
                self.metadata[entry[0]] = entry[1].lstrip()
        elif self.debug:
            print(f"Module {self.module} not found")

    def add(self, entry):
        if entry not in self.record:
            self.record.append(entry)

    def get(self, attribute):
        if attribute in self.metadata:
            return self.metadata[attribute].lstrip()
        return ""

    def get_record(self):
        return self.record

    def valid_module(self):
        return self.module_valid

    def show_record(self):
        for r in self.record:
            print(r)

    def analyze(self, parent, dependencies):
        if len(dependencies) == 0:
            return
        else:
            for r in dependencies.split(","):
                self.set_module(r)
                self.process_module()
                # Only process module for dependencies if valid
                if self.valid_module():
                    self.add(
                        [
                            parent.lower().replace("_", "-"),
                            self.get("Name").lower().replace("_", "-"),
                            self.get("Version"),
                            self.get("Author"),
                            self.get("License"),
                        ]
                    )
                    self.analyze(r.strip(), self.get("Requires"))
