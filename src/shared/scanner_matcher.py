from typing import Dict, List, Optional, Pattern


def read_url_suffix(text_piece: str, start_idx: int) -> str:
    suffix_chars = []
    for char in text_piece[start_idx:]:
        if char.isspace() or char in "\"'`<>()[]{};,":
            break
        suffix_chars.append(char)
    return "".join(suffix_chars)

# Some providers use URLs where the useful part continues past the regex match.
# For example, Firebase REST endpoints are only valid if the expanded URL includes ".json".
def normalize_match(api_name: str, text_piece: str, hit) -> Optional[str]:
    secret = hit.group(0)
    if api_name != "Firebase Database URL":
        return secret

    expanded_secret = secret + read_url_suffix(text_piece, hit.end())
    if ".json" not in expanded_secret.lower():
        return None
    return expanded_secret

# This scans one decoded text blob and records normalized findings with file and line metadata.
def regex_grep_text(
    raw_text: str,
    filename: str,
    api_signatures: Dict[str, Pattern[str]],
    line_cutoff: int,
) -> List[dict]:
    caught_keys = []
    for line_idx, line_data in enumerate(raw_text.splitlines(), 1):
        if len(line_data) > line_cutoff:
            split_pieces = [line_data[i:i + line_cutoff] for i in range(0, len(line_data), line_cutoff)]
        else:
            split_pieces = [line_data]

        for piece in split_pieces:
            for api_name, regex_obj in api_signatures.items():
                for hit in regex_obj.finditer(piece):
                    normalized_secret = normalize_match(api_name, piece, hit)
                    if not normalized_secret:
                        continue
                    caught_keys.append({
                        "file": filename,
                        "line": line_idx,
                        "type": api_name,
                        "secret": normalized_secret,
                    })
    return caught_keys
