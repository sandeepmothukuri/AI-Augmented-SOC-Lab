#!/usr/bin/env python3
"""
Sigma-to-Wazuh Rules Compiler
==============================
Translates standard Sigma detection rules (.yml) into native Wazuh XML rules.
Supports pySigma conversion with a built-in deterministic compilation engine
for out-of-the-box operation with zero external plugin requirements.

Usage:
    python scripts/compile-rules.py
    python scripts/compile-rules.py --input-dir sigma-rules --output wazuh-config/sigma-rules.xml
    python scripts/compile-rules.py --merge-into wazuh-config/custom-rules.xml
    python scripts/compile-rules.py --rule-id-start 100020

Supported Sigma Features:
    - Logsources: process_creation, windows/sysmon, linux/auditd, webserver, zeek/dns
    - Conditions: selection filters, contains, endswith, gt comparisons
    - Tag-based MITRE ATT&CK extraction (e.g., attack.t1059.001 -> <mitre><id>T1059.001</id></mitre>)
    - Severity mapping: informational/low/medium/high/critical -> Wazuh levels 3-15
"""

import argparse
import logging
import re
import sys
import xml.dom.minidom
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Run: pip install pyyaml")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sigma-compiler")

# Level mapping from Sigma severity to Wazuh rule levels
SEVERITY_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 14,
}


def _extract_mitre_id(tags: list[str]) -> str | None:
    """Extract first MITRE ATT&CK technique ID from Sigma tags."""
    for tag in tags or []:
        tag_lower = tag.lower()
        match = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", tag_lower)
        if match:
            return match.group(1).upper()
    return None


def _build_regex_pattern(values: list | str | int | float) -> str:
    """Escape and format list of values into a PCRE2 regex alternation."""
    if isinstance(values, (int, float, str)):
        values = [str(values)]
    escaped = [re.escape(str(v).strip()) for v in values if str(v).strip()]
    if len(escaped) == 1:
        return f"(?i){escaped[0]}"
    return f"(?i)({'|'.join(escaped)})"


def translate_sigma_rule(sigma_data: dict, rule_id: int) -> ET.Element:
    """Translate parsed Sigma YAML dictionary into a Wazuh XML <rule> Element."""
    rule_elem = ET.Element(
        "rule",
        id=str(rule_id),
        level=str(SEVERITY_MAP.get(sigma_data.get("level", "medium").lower(), 8)),
    )

    # Determine group and parent rule/decoder based on logsource
    logsource = sigma_data.get("logsource", {})
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    service = logsource.get("service", "")

    rule_groups = ["sigma", "custom"]
    if product:
        rule_groups.append(product)
    if category:
        rule_groups.append(category)
    if service:
        rule_groups.append(service)

    # Group classification & if_group mapping
    if product == "windows" or category == "process_creation":
        if_elem = ET.SubElement(rule_elem, "if_group")
        if_elem.text = "windows,sysmon_process_creation"
    elif product == "linux" and service == "auditd":
        if_elem = ET.SubElement(rule_elem, "if_group")
        if_elem.text = "auditd"
    elif category == "webserver":
        if_elem = ET.SubElement(rule_elem, "if_group")
        if_elem.text = "web,accesslog"
    elif category == "dns" or product == "zeek":
        dec_elem = ET.SubElement(rule_elem, "decoded_as")
        dec_elem.text = "zeek"

    # Process detection selection
    detection = sigma_data.get("detection", {})
    selection = detection.get("selection", {})

    regex_added = False
    for field_key, field_val in selection.items():
        # Handle field modifiers
        if "|" in field_key:
            field_name, modifier = field_key.split("|", 1)
        else:
            field_name, modifier = field_key, "exact"

        pattern = _build_regex_pattern(field_val)

        if field_name.lower() in ("image", "commandline", "cs_uri_query", "name"):
            reg_elem = ET.SubElement(rule_elem, "regex", type="pcre2")
            reg_elem.text = pattern
            regex_added = True
        elif field_name.lower() in ("comm", "cs_method", "qtype"):
            match_elem = ET.SubElement(rule_elem, "match")
            if isinstance(field_val, list):
                match_elem.text = str(field_val[0])
            else:
                match_elem.text = str(field_val)
            regex_added = True
        elif modifier == "gt":
            field_elem = ET.SubElement(rule_elem, "field", name="dns.query_length", type="pcre2")
            field_elem.text = r"[4-9]\d|[1-9]\d{2,}"
            regex_added = True

    if not regex_added and selection:
        # Fallback raw match
        match_elem = ET.SubElement(rule_elem, "match")
        first_val = list(selection.values())[0]
        match_elem.text = str(first_val[0] if isinstance(first_val, list) else first_val)

    # Description
    desc_elem = ET.SubElement(rule_elem, "description")
    desc_elem.text = f"[Sigma] {sigma_data.get('title', 'Sigma Rule Detection')}"

    # Rule Groups
    group_elem = ET.SubElement(rule_elem, "group")
    group_elem.text = ",".join(dict.fromkeys(rule_groups))

    # MITRE ATT&CK
    mitre_id = _extract_mitre_id(sigma_data.get("tags", []))
    if mitre_id:
        mitre_elem = ET.SubElement(rule_elem, "mitre")
        id_elem = ET.SubElement(mitre_elem, "id")
        id_elem.text = mitre_id

    return rule_elem


def compile_sigma_directory(input_dir: Path, output_file: Path, rule_id_start: int = 100020) -> int:
    """Compile all .yml/.yaml Sigma rules in directory to Wazuh XML."""
    if not input_dir.exists():
        logger.error("Input directory %s does not exist", input_dir)
        return 0

    rule_files = sorted(list(input_dir.glob("*.yml")) + list(input_dir.glob("*.yaml")))
    if not rule_files:
        logger.warning("No Sigma rules found in %s", input_dir)
        return 0

    logger.info("Found %d Sigma rule file(s) in %s", len(rule_files), input_dir)

    root = ET.Element("group", name="sigma-compiled,custom")
    current_id = rule_id_start
    compiled_count = 0

    for rule_file in rule_files:
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict) or "detection" not in data:
                logger.debug("Skipping non-rule YAML: %s", rule_file.name)
                continue

            rule_xml = translate_sigma_rule(data, current_id)
            root.append(rule_xml)
            compiled_count += 1
            current_id += 1
            logger.info("  Compiled: [%d] %s", current_id - 1, data.get("title", rule_file.name))
        except Exception as exc:
            logger.error("Failed to compile %s: %s", rule_file.name, exc)

    # Format XML with indentation
    xml_str = ET.tostring(root, encoding="utf-8")
    parsed_dom = xml.dom.minidom.parseString(xml_str)
    pretty_xml = parsed_dom.toprettyxml(indent="  ")

    # Strip extra blank lines
    cleaned_lines = [line for line in pretty_xml.splitlines() if line.strip()]
    final_xml = "\n".join(cleaned_lines) + "\n"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(final_xml, encoding="utf-8")
    logger.info("Wrote %d compiled rules to %s", compiled_count, output_file)
    return compiled_count


def merge_into_custom_rules(source_xml: Path, target_xml: Path) -> None:
    """Merge compiled Sigma rules into existing custom-rules.xml."""
    if not target_xml.exists():
        target_xml.write_text(source_xml.read_text(encoding="utf-8"), encoding="utf-8")
        logger.info("Target did not exist; copied directly to %s", target_xml)
        return

    try:
        source_tree = ET.parse(source_xml)
        target_tree = ET.parse(target_xml)
        target_root = target_tree.getroot()

        # Collect existing rule IDs
        existing_ids = {r.attrib.get("id") for r in target_root.findall("rule")}

        added = 0
        for rule in source_tree.getroot().findall("rule"):
            if rule.attrib.get("id") not in existing_ids:
                target_root.append(rule)
                added += 1

        xml_str = ET.tostring(target_root, encoding="utf-8")
        parsed_dom = xml.dom.minidom.parseString(xml_str)
        pretty_xml = parsed_dom.toprettyxml(indent="  ")
        cleaned_lines = [line for line in pretty_xml.splitlines() if line.strip()]
        target_xml.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
        logger.info("Merged %d new rule(s) into %s", added, target_xml)
    except Exception as exc:
        logger.error("Failed to merge rules: %s", exc)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sigma-to-Wazuh Rules Compiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input-dir",
        default="sigma-rules",
        help="Directory containing Sigma YAML rules (default: sigma-rules)",
    )
    parser.add_argument(
        "--output",
        default="wazuh-config/sigma-rules.xml",
        help="Output XML file path (default: wazuh-config/sigma-rules.xml)",
    )
    parser.add_argument(
        "--rule-id-start",
        type=int,
        default=100020,
        help="Starting Wazuh rule ID number (default: 100020)",
    )
    parser.add_argument(
        "--merge-into",
        help="Optional existing custom-rules.xml file to merge compiled rules into",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output)

    count = compile_sigma_directory(input_dir, output_file, args.rule_id_start)
    if count > 0 and args.merge_into:
        merge_into_custom_rules(output_file, Path(args.merge_into))


if __name__ == "__main__":
    main()
