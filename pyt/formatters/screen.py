#취약점을 색상으로 표시된 텍스트 형식으로 출력해주는 모듈이다
from ..vulnerabilities.vulnerability_helper import SanitisedVulnerability, UnknownVulnerability

RESET = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
DANGER = '\033[31m'
GOOD = '\033[32m'
HIGHLIGHT = '\033[45;1m'
RED_ON_WHITE = '\033[31m\033[107m'


def color(string, color_string): #문자열에 색상을 입혀서 return 해준다
    return color_string + str(string) + RESET 


def report(
    vulnerabilities,
    fileobj,
    print_sanitised,
):
    """
    취약점을 색상으로 표시된 텍스트 형식으로 출력해준다

    vulnerabilities : 보고 할 취약점 목록
    file obj : 출력 파일 객체
    """
    n_vulnerabilities = len(vulnerabilities)  #n_vulnerabilities는 vulnerabilities의 길이
    unsanitised_vulnerabilities = [v for v in vulnerabilities if not isinstance(v, SanitisedVulnerability)]  #unsanitised_vulnerabilities는 SanitisedVulnerability의 인스턴스가 아닌 v 리스트
    n_unsanitised = len(unsanitised_vulnerabilities) #n_unsanitised는 unsanitised_vulnerabilities의 길이
    n_sanitised = n_vulnerabilities - n_unsanitised
    #찾은 취약점과 그 취약점을 해결한 후 출력해준다
    heading = "{} 취약{}이 발견되고 {} 처리되었습니다.\n".format(
        '0개의' if n_unsanitised == 0 else '{}개의'.format(n_unsanitised),
        '점' if n_unsanitised == 1 else '점들',
        " ({}개의 취약점이)".format(n_sanitised) if n_sanitised else "",
    )
    vulnerabilities_to_print = vulnerabilities if print_sanitised else unsanitised_vulnerabilities
    with fileobj: #취약점을 열거한다
        for i, vulnerability in enumerate(vulnerabilities_to_print, start=1):
            fileobj.write(vulnerability_to_str(i, vulnerability))

        if n_unsanitised == 0: #감염된 소스가 없다면 아래를 실행
            fileobj.write(color(heading, GOOD))
        else:
            fileobj.write(color(heading, DANGER))


def vulnerability_to_str(i, vulnerability): #취약점을 찾아 색상으로 표시된 텍스트 형식으로 바꿔준다
    lines = [] #리스트 생성
    lines.append(color('취약점 개수 {}'.format(i), UNDERLINE)) #취약점을 리스트에 추가
    lines.append('파일 경로: {}'.format(color(vulnerability.source.path, BOLD))) #취약점의 파일 경로를 찾아 리스트에 추가
    lines.append( #취약점이 발생한 라인의 번호와 취약점을 발생시키는 단어(변수)를 찾아 리스트에 추가
        '{}번째 줄에 소스가 있습니다. 소스 발생 : "{}":'.format(
            vulnerability.source.line_number,
            color(vulnerability.source_trigger_word, HIGHLIGHT),
        ) 
    )
    lines.append('\t{}'.format(color(vulnerability.source.label, RED_ON_WHITE))) #취약점의 label을 리스트에 추가
    a.input('취약점을 고치시겠습니까?\nYes/No')
    if a=='Yes':
    
        if vulnerability.reassignment_nodes: #취약점으로 인해 재할당된 노드라면 아래를 실행
            previous_path = None
            lines.append('취약점을 재할당한 곳:') #재할당된 노드를 추가해준다
            for node in vulnerability.reassignment_nodes: #재할당된 노드들에 대해 반복
                if node.path != previous_path: #노드의 경로와 그 전의 경로와 다르면 아래를 실행
                    lines.append('\t파일 경로: {}'.format(node.path)) #재할당한 파일 이름을 리스트에 추가
                    previous_path = node.path
                label = node.label
                if ( #vulnerability가 unsanitised_vulnerability의 인스턴스고 노드의 label이 취약점을 해결한 노드의 label과 같으면 아래를 실행
                    isinstance(vulnerability, SanitisedVulnerability) and
                    node.label == vulnerability.sanitiser.label
                ):
                    label = color(label, GOOD)
                lines.append( #label과 줄번호를 리스트에 추가
                    '\t{}번째 줄:\t{}'.format(
                        node.line_number,
                        label,
                    )
                )
        elif a==No:
            exit();
        else:
            lines.append('잘못된 입력값입니다.')
    if vulnerability.source.path != vulnerability.sink.path: #source의 경로와 sink의 경로가 다르면 아래를 실행
        lines.append('파일 경로: {}'.format(color(vulnerability.sink.path, BOLD))) #sink의 경로를 리스트에 추가
    lines.append(
        '{}번째 줄에 싱크가 있습니다. 싱크 발생 : "{}"'.format(
            vulnerability.sink.line_number,
            color(vulnerability.sink_trigger_word, HIGHLIGHT), #sink를 발생시키는 단어(변수)와 줄 번호를 리스트에 추가
        )
    )
    lines.append('\t{}'.format(
        color(vulnerability.sink.label, RED_ON_WHITE) #sink의 label을 리스트에 추가
    ))
    if isinstance(vulnerability, SanitisedVulnerability): #vulnerability가 SanitisedVulnerability의 인스턴스면 아래를 실행
        lines.append( 
            '이 취약점은 {}로 인해 {}{}'.format(
                color(vulnerability.sanitiser.label, BOLD),
                color('잠재적으로 ', BOLD) if not vulnerability.confident else '',
                color('취약점이 처리되었습니다', GOOD),
            )
        )
    elif isinstance(vulnerability, UnknownVulnerability): #vulnerability가 UnknownVulnerability의 인스턴스면 아래를 실행
        lines.append(
            '이 취약점은 "{}" 때문에 발견되지 않았다.'.format(
                color(vulnerability.unknown_assignment.label, BOLD),
            )
        )
    return '\n'.join(lines) + '\n\n' #리스트 반환
