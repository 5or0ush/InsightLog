from asyncio.log import logger
import os
import re
import calendar
import os
import io
from insightlog.settings import *
from insightlog.validators import *

from datetime import datetime
import logging


def get_service_settings(service_name):
    """
    Get default settings for the said service
    :param service_name: service name (example: nginx, apache2...)
    :return: service settings if found or None
    """
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception("Service \""+service_name+"\" doesn't exists!")


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):
    """
    Get the date pattern that can be used to filter data from logs based on the params
    :raises Exception:
    :param settings: dict
    :param minute: int
    :param hour: int
    :param day: int
    :param month: int
    :param year: int
    :return: string
    """
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")
    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise Exception("Date elements aren't valid")
    return date_filter


def filter_data(
    log_filter,
    data=None,
    filepath=None,
    is_casesensitive=True,
    is_regex=False,
    is_reverse=False,
    encoding='utf-8',     # NEW: allows you to choose the file encoding
    errors='strict'       # NEW: decoding error policy: 'strict' | 'replace' | 'ignore'
):
    """
    Filter received data/file content and return the results
    :except IOError:
    :except EnvironmentError:
    :raises Exception:
    :param log_filter: string
    :param data: string
    :param filepath: string
    :param is_casesensitive: boolean
    :param is_regex: boolean
    :param is_reverse: boolean to inverse selection
    :return: string
    """
    return_data = ""
if filepath:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                    return_data += line
        return return_data
    except (IOError, OSError) as e:
        logging.error("Failed to read log file %s: %s", filepath, e)
        raise
elif data is not None:
    for line in data.splitlines():
        if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
            return_data += line + "\n"
    return return_data
else:
    raise ValueError("Either 'data' or 'filepath' must be provided.")


def check_match(line, filter_pattern, is_regex, is_casesensitive, is_reverse):
    """
    Check if line contains/matches filter pattern
    :param line: string
    :param filter_pattern: string
    :param is_regex: boolean
    :param is_casesensitive: boolean
    :param is_reverse: boolean
    :return: boolean
    """
    if is_regex:
        check_result = re.search(filter_pattern, line) if is_casesensitive \
            else re.search(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    return check_result and not is_reverse


def get_web_requests(data, pattern, date_pattern=None, date_keys=None):
    """
    Analyze data (from the logs) and return list of requests formatted as the model (pattern) defined.
    :param data: string
    :param pattern: string
    :param date_pattern: regex|None
    :param date_keys: dict|None
    :return: list
    """
    # BUG: Output format inconsistent with get_auth_requests
    # fix BUG: No handling/logging for malformed lines
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    compiled = re.compile(pattern, flags=re.IGNORECASE)
    requests = []
    expected_groups = 7  # IP, DATETIME/RAW, METHOD, ROUTE, CODE, REFERRER, USERAGENT

    for lineno, line in enumerate(data.splitlines(), start=1):
        m = compiled.search(line)
        if not m:
            logger.warning("get_web_requests: unmatched line %d: %s", lineno, line.strip())
            continue

        request_tuple = m.groups()
        if len(request_tuple) < expected_groups:
            logger.warning("get_web_requests: malformed line %d (groups=%d, expected=%d): %s",
                           lineno, len(request_tuple), expected_groups, line.strip())
            continue

        try:
            if date_pattern:
                str_datetime = __get_iso_datetime(request_tuple[1], date_pattern, date_keys)
            else:
                str_datetime = request_tuple[1]
        except Exception as e:
            logger.warning("get_web_requests: invalid datetime at line %d: %s (error=%s)",
                           lineno, line.strip(), e)
            continue

        try:
            requests.append({
                'DATETIME': str_datetime,
                'IP': request_tuple[0],
                'METHOD': request_tuple[2],
                'ROUTE': request_tuple[3],
                'CODE': request_tuple[4],
                'REFERRER': request_tuple[5],
                'USERAGENT': request_tuple[6]
            })
        except Exception as e:
            logger.warning("get_web_requests: unexpected build error at line %d: %s (error=%s)",
                           lineno, line.strip(), e)
            continue

    return requests


def get_auth_requests(data, pattern, date_pattern=None, date_keys=None):
    """
    Analyze data (from the logs) and return list of auth requests formatted as the model (pattern) defined.
    :param data: string
    :param pattern: string
    :param date_pattern:
    :param date_keys:
    :return: list of dicts
    """
    requests_dict = re.findall(pattern, data)
    requests = []
    for request_tuple in requests_dict:
        if date_pattern:
            str_datetime = __get_iso_datetime(request_tuple[0], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[0]
        data = analyze_auth_request(request_tuple[2])
        data['DATETIME'] = str_datetime
        data['SERVICE'] = request_tuple[1]
        requests.append(data)
    return requests


def analyze_auth_request(request_info):
    """
    Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)
    :param request_info: string
    :return: dicts
    """
    text = request_info if isinstance(request_info, str) else str(request_info)

    ipv4 = re.findall(IPv4_REGEX, text)
    lower = text.lower()
    is_preauth = '[preauth]' in lower
    invalid_user = re.findall(AUTH_USER_INVALID_USER, text)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, text)
    is_closed = 'connection closed by ' in lower

    if not (ipv4 or invalid_user or invalid_pass_user or is_preauth or is_closed):
        logging.warning("Malformed auth log line: %r", text.strip())

    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed}


def __get_iso_datetime(str_date, pattern, keys):
    """
    Change raw datetime from logs to ISO 8601 format.
    :param str_date: string
    :param pattern: regex (date_pattern from settings)
    :param keys: dict (date_keys from settings)
    :return: string
    """
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    a_date = re.findall(pattern, str_date)[0]
    d_datetime = datetime(int(a_date[keys['year']]) if 'year' in keys else __get_auth_year(),
                          months_dict[a_date[keys['month']]], int(a_date[keys['day']].strip()),
                          int(a_date[keys['hour']]), int(a_date[keys['minute']]), int(a_date[keys['second']]))
    return d_datetime.isoformat(' ')


def __get_auth_year():
    """
    Return the analysis year.
    Uses environment override INSIGHTLOG_AUTH_YEAR if set; otherwise current year.
    """
    override = os.getenv("INSIGHTLOG_AUTH_YEAR")
    if override and override.isdigit():
        return int(override)
    return datetime.now().year


class InsightLogAnalyzer:

    def __init__(self, service, data=None, filepath=None):
        """
        Constructor, define service (nginx, apache2...), set data or filepath if needed
        :param service: string: service name (nginx, apache2...)
        :param data: string: data to be filtered if not from a file
        :param filepath: string: file path from which the data will be loaded if data isn't defined
        and you are not using the default service logs filepath
        :return:
        """
        self.__filters = []
        self.__settings = get_service_settings(service)
        self.data = data
        if filepath:
            self.filepath = filepath
        else:
            self.filepath = self.__settings['dir_path']+self.__settings['accesslog_filename']

    def add_filter(self, filter_pattern, is_casesensitive=True, is_regex=False, is_reverse=False):
        """
        Add filter data the filters list
        :param filter_pattern: boolean
        :param is_casesensitive: boolean
        :param is_regex: boolean
        :param is_reverse: boolean
        :return:
        """
        self.__filters.append({
            'filter_pattern': filter_pattern,
            'is_casesensitive': is_casesensitive,
            'is_regex': is_regex,
            'is_reverse': is_reverse
        })

    def add_date_filter(self, minute=datetime.now().minute, hour=datetime.now().hour,
                        day=datetime.now().day, month=datetime.now().month, year=datetime.now().year):
        """
        Set datetime filter
        :param minute: int
        :param hour: int
        :param day: int
        :param month: int
        :param year: int
        """
        date_filter = get_date_filter(self.__settings, minute, hour, day, month, year)
        self.add_filter(date_filter)

    def get_all_filters(self):
        """
        return all defined filters
        :return: List
        """
        return self.__filters

    def get_filter(self, index):
        """
        Get a filter data by index
        :param index:
        :return: Dictionary
        """
        return self.__filters[index]

    def remove_filter(self, index):
        """
        Remove one filter from filters list using it's index
        :param index:
        :return:
        """
        # BUG: This method does not remove by index
        self.__filters.remove(index)

    def clear_all_filters(self):
        """
        Clear all filters
        :return:
        """
        self.__filters = []

    def check_all_matches(self, line, filter_patterns):
        """
        Check if line contains/matches all filter patterns
        :param line: String
        :param filter_patterns: List of dictionaries containing
        :return: boolean
        """
        if not filter_patterns:
            return True  # No filters means include all lines
        to_return = None
        for pattern_data in filter_patterns:
            tmp_result = check_match(line=line, **pattern_data)
            to_return = tmp_result if to_return is None else (tmp_result and to_return)
        return to_return

    def filter_all(self):
        """
        Apply all defined patterns and return filtered data
        :return: string
        """
        # FIX BUG: Large files are read into memory at once (performance issue)
        # BUG: No warning or log for empty files
        # Stream lines to avoid loading entire files or building large intermediate lists.
        # Also warn if the input source is empty.
        out_lines = []

        if self.data is not None:
            if self.data == "":
                logger.warning("filter_all: empty in-memory data")
                return ""
            # Iterate lazily over the string without splitlines() list allocation
            for line in io.StringIO(self.data):
                if self.check_all_matches(line, self.__filters):
                # Ensure newline termination
                    out_lines.append(line if line.endswith("\n") else line + "\n")
        else:
        # File path mode
            try:
                size = os.path.getsize(self.filepath)
            except OSError as e:
                logger.error("filter_all: cannot stat %s: %s", self.filepath, e)
                raise
        if size == 0:
            logger.warning("filter_all: empty file: %s", self.filepath)
            return ""

        # Use explicit encoding and error policy to be consistent
        with open(self.filepath, "r", encoding="utf-8", errors="strict") as file_object:
            for line in file_object:
                if self.check_all_matches(line, self.__filters):
                    out_lines.append(line)

        return "".join(out_lines)
      

    def get_requests(self, output_format='dict'):
        """
        Analyze data (from the logs) and return requests in specified format.
        Supported formats: 'dict', 'json', 'csv'.
        :param output_format: string specifying output format
        :return: data in specified format
        """
        data = self.filter_all()
        request_pattern = self.__settings['request_model']
        date_pattern = self.__settings['date_pattern']
        date_keys = self.__settings['date_keys']

        if self.__settings['type'] == 'web0':
            requests = get_web_requests(data, request_pattern, date_pattern, date_keys)
        elif self.__settings['type'] == 'auth':
            requests = get_auth_requests(data, request_pattern, date_pattern, date_keys)
        else:
            requests = []

        if output_format == 'dict':
            return requests
        elif output_format == 'json':
            import json
            return json.dumps(requests)
        elif output_format == 'csv':
            import csv
            import io
            if not requests:
                return ""
            # Get headers from keys of first dict
            headers = requests[0].keys()
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=headers)
            writer.writeheader()
            for row in requests:
                writer.writerow(row)
            return output.getvalue()
        else:
            raise Exception("Unsupported output format: " + output_format)

    # TODO: Add log level filtering (e.g., only errors)
    def add_log_level_filter(self, level):
        """
        Add a filter for log level (e.g., ERROR, WARNING)
        :param level: string
        """
        pass  # Feature stub

    # TODO: Add support for time range filtering
    def add_time_range_filter(self, start, end):
        """
        Add a filter for a time range
        :param start: datetime
        :param end: datetime
        """
        pass  # Feature stub

    # TODO: Add export to CSV
    def export_to_csv(self, path):
        """
        Export filtered results to a CSV file
        :param path: string
        """
        csv_data = self.get_requests('csv')
        with open(path, 'w', newline='') as csvfile:
            csvfile.write(csv_data)

# TODO: Write more tests for edge cases, error handling, and malformed input
