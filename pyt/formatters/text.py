#일반 텍스트 형식으로 취약점을 출력하는 모듈이다
from ..vulnerabilities.vulnerability_helper import SanitisedVulnerability


def report(
    vulnerabilities,
    fileobj,
    print_sanitised,
):
    """
    취약점을 텍스트 형식으로 출력한다

    vulnerabilities : 보고 할 취약점 목록
    file obj : 출력 파일 객체
    print_sanitised: 취약점을 해결한 후의 취약점 출력
    """
    n_vulnerabilities = len(vulnerabilities) #n_vulnerabilities는 vulnerabilities의 길이
    unsanitised_vulnerabilities = [v for v in vulnerabilities if not isinstance(v, SanitisedVulnerability)] #unsanitised_vulnerabilities는 SanitisedVulnerability의 인스턴스가 아닌 v 리스트
    n_unsanitised = len(unsanitised_vulnerabilities) #n_unsanitised는 unsanitised_vulnerabilities의 길이
    n_sanitised = n_vulnerabilities - n_unsanitised 
    #찾은 취약점과 그 취약점을 해결한 후 출력해준다
    heading = "{} 취약{}이 발견되고 {} 처리되었습니다.{}\n".format( 
        '0개의' if n_unsanitised == 0 else '{}개의'.format(n_unsanitised),
        '점' if n_unsanitised == 1 else '점들',
        " ({}개의 취약점이)".format(n_sanitised) if n_sanitised else "",
        ':' if n_vulnerabilities else '.',
    )
    vulnerabilities_to_print = vulnerabilities if print_sanitised else unsanitised_vulnerabilities
    with fileobj:
        fileobj.write(heading) #결과를 출력

        for i, vulnerability in enumerate(vulnerabilities_to_print, start=1): #취약점을 열거한다
            fileobj.write('취약점 {}:\n{}\n\n'.format(i, vulnerability))
