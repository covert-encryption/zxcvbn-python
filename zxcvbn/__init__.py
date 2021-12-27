import re
import time
from datetime import timedelta
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, TypedDict

from . import feedback, matching, scoring, time_estimates, types


def zxcvbn(password: str, user_inputs: Optional[Iterable[str]] = None) -> types.Result:
    start = time.perf_counter()

    # Find unique non-empty user inputs, split words lower-cased, preserving order
    wordsep = re.compile(r"\W+|_")
    sanitized_inputs = list(dict.fromkeys(
        s.lower()
        for u in user_inputs or []
        for s in re.split(wordsep, u)
        if s
    ))
    ranked_dictionaries = matching.RANKED_DICTIONARIES
    ranked_dictionaries["user_inputs"] = matching.build_ranked_dict(sanitized_inputs)

    matches = matching.omnimatch(password, ranked_dictionaries)
    result: types.Result = scoring.most_guessable_match_sequence(password, matches)  # type: ignore
    result['calc_time'] = timedelta(microseconds=1e6 * (time.perf_counter() - start))

    attack_times = time_estimates.estimate_attack_times(result["guesses"])
    for prop, val in attack_times.items():
        result[prop] = val  # type: ignore

    result["feedback"] = feedback.get_feedback(result["score"], result["sequence"])

    return result
