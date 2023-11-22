from datetime import datetime



def prettify_elapsed_time(seconds):
    """
    Convert the specified seconds value into days|hours|minutes|seconds.
    Will start with largest type, days, and continue drilling down.
        - Credit: # https://gist.github.com/thatalextaylor/7408395

    Example returns     1d 4h37m13s

    """
    sign_string = "-" if seconds < 0 else ""
    seconds = abs(int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    time_delta = sign_string

    if days > 0:
        time_delta += f"{days}d "
    if hours > 0:
        time_delta += f"{hours}h"
    if minutes > 0:
        time_delta += f"{minutes}m"
    if seconds > 0:
        time_delta += f"{seconds}s"

    return time_delta


def convert_string_to_datetime(raw_string):
    """
    Convert a raw timestamp string to a date & time string.
    """
    # input_date_format = "%Y-%m-%d %I:%M:%S %p"  # 12-hr time with AM/PM
    # output_date_format = "%Y-%m-%d %H:%M:%S"    # 24-hr time
    date_obj = None
    found = False
    input_date_formats = [
        # "%Y-%m-%d %I:%M:%S %p",
        # "%d/%m/%Y %I:%M %p",
        # "%b %d, %Y",
        # "%b. %d, %Y",
        # "%d-%b-%y",
        # "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%I:%M:%S+00:00",
        "%Y-%m-%dT%I:%M:%S.%f",
        # "%m/%d/%Y",
    ]

    while 1:
        for format in input_date_formats:
            try:
                # log.debug(f"Checking date pattern: {format=}")
                date_obj = datetime.strptime(raw_string, format)
                found = True
            except ValueError as e:
                # log.debug(f"ValueError exception: {e}")
                continue
            # If we manage to create a datetime object without exception, we found
            # the right pattern
            # log.debug(f"Found correct datetime pattern: {format=}")
            break

        if not found:
            # log.warn(f"Did not find correct datetime pattern from this string: {raw_string=}")
            # Try this method as fallback
            date_obj = datetime.fromisoformat(raw_string)
        break

    # date_obj = datetime.strptime(raw_string, input_date_format)
    # Output format: YYYY-MM-DD HH:MM:SS
    # return f"{date_obj:%Y-%m-%d %H:%M:%S}"
    return date_obj