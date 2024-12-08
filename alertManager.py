import sys
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from db import SessionLocal
from models import Server, CPE as CPEModel
from cpe import CPE

path = '/run/gvmd/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()

username = 'admin'
password = 'admin'


def cpe_extractor():
    global session
    try:
        reports = []
        cpe_dict = {}
        session = SessionLocal()

        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)

            tasks = gmp.get_tasks()

            for task in tasks.xpath('task'):
                last_report = task.find('.//last_report/report')
                if last_report is not None:
                    last_report_id = last_report.attrib['id']
                    reports.append(last_report_id)

            for report_id in reports:
                report = gmp.get_report(report_id)
                results = report.xpath('report/report/results/result/description')
                for result in results:
                    cpes_text = result.text
                    if cpes_text and '|cpe' in cpes_text:
                        lines = cpes_text.strip().split('\n')
                        for line in lines:
                            if '|cpe' in line:
                                ip_part, cpe_part = line.split('|', 1)
                                ip = ip_part.strip()
                                cpe_name = cpe_part.strip()

                                # Normalize the CPE to CPE 2.3 formatted string
                                try:
                                    cpe_obj = CPE(cpe_name)
                                    cpe_2_3_str = cpe_obj.as_fs()
                                except Exception as e:
                                    print(f"Error parsing CPE {cpe_name}: {e}", file=sys.stderr)
                                    continue  # Skip this CPE if it cannot be parsed

                                if ip not in cpe_dict:
                                    cpe_dict[ip] = set()
                                cpe_dict[ip].add(cpe_2_3_str)

        for ip, cpes in cpe_dict.items():
            server = session.query(Server).filter_by(ip=ip).first()
            if not server:
                server = Server(ip=ip, port='', overall_status='')
                session.add(server)
                session.commit()

            session.query(CPEModel).filter_by(server_id=server.id).delete()
            session.commit()

            new_cpes = [CPEModel(server_id=server.id, cpe_name=cpe_name) for cpe_name in cpes]
            session.bulk_save_objects(new_cpes)
            session.commit()

        session.close()

    except GvmError as e:
        print('An error occurred', e, file=sys.stderr)
    except Exception as e:
        print('An error occurred, remember to use sudo', e, file=sys.stderr)
        session.rollback()
        session.close()
