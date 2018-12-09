#json파일에서의 문제를 출력하기 위한 formatter다

import json
from datetime import datetime

from ..vulnerabilities.vulnerability_helper import SanitisedVulnerability


def report(
    vulnerabilities,
    fileobj,
    print_sanitised,
):
    
    """
    json 형식의 문제점을 출력한다

    vulnerabilities : 보고 할 취약점 목록
    file obj : 출력 파일 객체
    """
    TZ_AGNOSTIC_FORMAT = "%Y-%m-%dT%H:%M:%SZ" #python의 date time format이다
    time_string = datetime.utcnow().strftime(TZ_AGNOSTIC_FORMAT) #현재의 날짜와 시간을 반환한다

    #현재 시각과 취약점을 함께 출력해준다
    machine_output = { 
        '실행된 시각': time_string,
        '취약점': [
            vuln.as_dict() for vuln in vulnerabilities
            if print_sanitised or not isinstance(vuln, SanitisedVulnerability)
        ]
    }

    result = json.dumps(
        machine_output,
        indent=4
    )

    with fileobj:
        fileobj.write(result) #결과를 출력
