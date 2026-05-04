#!/usr/bin/env python3

import argparse
from pathlib import Path

from NTLFlowLyzer_udp.config_loader import ConfigLoader
from .network_flow_analyzer import NTLFlowLyzer

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='NTLFlowLyzer-UDP')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    parser.add_argument('-b', '--batch-mode', action='store_true',
                        help='Analyze all the files in the given directory. The default is False.')
    parser.add_argument('-cb', '--continues-batch-mode', action='store_true',
                        help='Continues batch mode. Analyze files in the given directory continuously.'
                            ' Default is False.')
    return parser


def find_pcap_files(directory):
    # Batch mode is intentionally non-recursive: the caller supplies one
    # malware-family directory and receives one output directory for that label.
    p = Path(directory)
    files = []
    for ext in ("*.pcap", "*.pcapng"):
        files.extend([str(x) for x in p.glob(ext) if x.is_file()])
    return sorted(files)


def main():
    print("You initiated NTLFlowLyzer UDP!")
    parsed_arguments = args_parser().parse_args()
    config_file_address = "./NTLFlowLyzer_udp/config.json" if parsed_arguments.config_file is None else parsed_arguments.config_file
    online_capturing = parsed_arguments.online_capturing
    if not parsed_arguments.batch_mode:
        config = ConfigLoader(config_file_address)
        network_flow_analyzer = NTLFlowLyzer(config, online_capturing, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()
        return

    print(">> Batch mode is on!")
    config = ConfigLoader(config_file_address)
    batch_address = config.batch_address
    batch_address_output = config.batch_address_output
    pcap_files = find_pcap_files(batch_address)
    out_dir = Path(batch_address_output)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f">> {len(pcap_files)} number of files detected. Lets go for analyze them!")
    for file in pcap_files:
        print(100*"#")
        pcap_path = Path(file)
        output_file = out_dir / f"{pcap_path.name}.csv"

        config.pcap_file_address = str(pcap_path)
        config.output_file_address = str(output_file)
        network_flow_analyzer = NTLFlowLyzer(config, online_capturing, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()


if __name__ == "__main__":
    main()
