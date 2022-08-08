# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

""" Set up Output Formatting """

import json


class OutputManager:
    """Helper class for managing output to file and console."""

    def __init__(self, out_type="file", filename=None):
        self.out_type = out_type
        self.filename = filename
        if self.out_type == "file":
            self.file_handle = open(filename, "w")
        else:
            self.file_handle = None

    def close(self):
        # print("close...")
        if self.out_type == "file":
            # print("close file", self.file_handle)
            self.file_handle.close()

    def file_out(self, message):
        self.file_handle.write(message + "\n")

    def console_out(self, message):
        print(message)

    def show(self, message):
        if self.out_type == "file":
            self.file_out(message)
        else:
            self.console_out(message)


class SBOMOutput:
    """Output manager for SBOM data."""

    def __init__(self, filename="console", output_format="tag"):
        self.filename = filename
        self.output_format = output_format
        self.format_process = {
            "tag": self.format_tag_data,
            "json": self.format_json_data,
            "xml": self.format_tag_data,
            "dot": self.format_tag_data,
        }
        self.type = "console"
        if self.filename != "":
            self.type = "file"
        self.output_manager = OutputManager(self.type, self.filename)

    def format_json_data(self, data):
        json_data = json.dumps(data, indent=2)
        self.send_output(json_data)

    def format_tag_data(self, dataset):
        for data_item in dataset:
            self.send_output(data_item)

    def send_output(self, data):
        self.output_manager.show(data)

    def generate_output(self, dataset):
        self.format_process[self.output_format](dataset)
        # print("about to close")
        self.output_manager.close()
        # print("closed")
