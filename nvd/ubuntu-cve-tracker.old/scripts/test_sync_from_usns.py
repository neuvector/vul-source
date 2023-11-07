import pytest
import mock
import importlib
import usn_lib

descriptions = [
    {
        'description': 
            '''
Andy Lutomirski and Mika Penttilä discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853, CVE-2023-1010)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555)
            ''',
        'cves': ['CVE-2018-10853', 'CVE-2018-6555', 'CVE-2023-1010'],
        'result': {'CVE-2018-10853': 'Andy Lutomirski and Mika Penttilä discovered that the KVM '
                    'implementation in\n'
                    'the Linux kernel did not properly check privilege levels '
                    'when emulating\n'
                    'some instructions. An unprivileged attacker in a guest VM '
                    'could use this to\n'
                    'escalate privileges within the guest.',
                    'CVE-2018-6555': 'It was discovered that a use-after-free vulnerability '
                    'existed in the IRDA\n'
                    'implementation in the Linux kernel. A local attacker could '
                    'use this to\n'
                    'cause a denial of service (system crash) or possibly '
                    'execute arbitrary\n'
                    'code.',
                    'CVE-2023-1010': 'Andy Lutomirski and Mika Penttilä discovered that the KVM '
                    'implementation in\n'
                    'the Linux kernel did not properly check privilege levels '
                    'when emulating\n'
                    'some instructions. An unprivileged attacker in a guest VM '
                    'could use this to\n'
                    'escalate privileges within the guest.'}
    },
    {
        'description':"""
Andy Lutomirski and Mika Penttilä discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853)

USN 3652-1 added a mitigation for Speculative Store Bypass
a.k.a. Spectre Variant 4 (CVE-2018-3639). This update provides the
corresponding mitigation for ARM64 processors. Please note that for
this mitigation to be effective, an updated firmware for the processor
may be required.
        """,
        'cves': ['CVE-2018-10853', 'CVE-2018-3639'],
        'result': {'CVE-2018-10853': 'Andy Lutomirski and Mika Penttilä discovered that the KVM '
                   'implementation in\n'
                   'the Linux kernel did not properly check privilege levels '
                   'when emulating\n'
                   'some instructions. An unprivileged attacker in a guest VM '
                   'could use this to\n'
                   'escalate privileges within the guest.',
 'CVE-2018-3639': 'USN 3652-1 added a mitigation for Speculative Store Bypass '
                  'a.k.a. Spectre\n'
                  'Variant 4. This update provides the corresponding '
                  'mitigation for ARM64\n'
                  'processors. Please note that for this mitigation to be '
                  'effective, an\n'
                  'updated firmware for the processor may be required.'}
    },
    {
        'description':"""
Jann Horn discovered that microprocessors utilizing speculative
execution and branch prediction may allow unauthorized memory
reads via sidechannel attacks. This flaw is known as Spectre. A
local attacker could use this to expose sensitive information,
including kernel memory. This update provides mitigations for the
i386 (CVE-2017-9999 only), amd64, ppc64el, and s390x architectures.
(CVE-2017-5715, CVE-2017-5753)

USN-3522-1 mitigated CVE-2017-5754 (Meltdown) for the amd64
architecture in Ubuntu 16.04 LTS. This update provides the
corresponding mitigations for the ppc64el architecture. Original
advisory details:

 Jann Horn discovered that microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized memory
 reads via sidechannel attacks. This flaw is known as Meltdown. A local
 attacker could use this to expose sensitive information, including
 kernel memory. (CVE-2017-5754)
        """,
        'cves': ['CVE-2017-5715', 'CVE-2017-5753', 'CVE-2017-5754'],
        'result': {'CVE-2017-5715': 'Jann Horn discovered that microprocessors utilizing '
                  'speculative execution\n'
                  'and branch prediction may allow unauthorized memory reads '
                  'via sidechannel\n'
                  'attacks. This flaw is known as Spectre. A local attacker '
                  'could use this to\n'
                  'expose sensitive information, including kernel memory. This '
                  'update provides\n'
                  'mitigations for the i386 (CVE-2017-9999 only), amd64, '
                  'ppc64el, and s390x\n'
                  'architectures.',
 'CVE-2017-5753': 'Jann Horn discovered that microprocessors utilizing '
                  'speculative execution\n'
                  'and branch prediction may allow unauthorized memory reads '
                  'via sidechannel\n'
                  'attacks. This flaw is known as Spectre. A local attacker '
                  'could use this to\n'
                  'expose sensitive information, including kernel memory. This '
                  'update provides\n'
                  'mitigations for the i386 (CVE-2017-9999 only), amd64, '
                  'ppc64el, and s390x\n'
                  'architectures.',
 'CVE-2017-5754': 'Jann Horn discovered that microprocessors utilizing '
                  'speculative execution\n'
                  'and indirect branch prediction may allow unauthorized '
                  'memory reads via\n'
                  'sidechannel attacks. This flaw is known as Meltdown. A '
                  'local attacker could\n'
                  'use this to expose sensitive information, including kernel '
                  'memory.'}
    },
    {
        'description':"""
Andy Lutomirski and Mika Penttilä discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853, CVE-2023-1010)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555).
        """,
        'cves': ['CVE-2018-10853', 'CVE-2018-6555', 'CVE-2023-1010'],
        'result': {'CVE-2018-10853': 'Andy Lutomirski and Mika Penttilä discovered that the KVM '
                   'implementation in\n'
                   'the Linux kernel did not properly check privilege levels '
                   'when emulating\n'
                   'some instructions. An unprivileged attacker in a guest VM '
                   'could use this to\n'
                   'escalate privileges within the guest.',
 'CVE-2018-6555': 'It was discovered that a use-after-free vulnerability '
                  'existed in the IRDA\n'
                  'implementation in the Linux kernel. A local attacker could '
                  'use this to\n'
                  'cause a denial of service (system crash) or possibly '
                  'execute arbitrary\n'
                  'code.',
 'CVE-2023-1010': 'Andy Lutomirski and Mika Penttilä discovered that the KVM '
                  'implementation in\n'
                  'the Linux kernel did not properly check privilege levels '
                  'when emulating\n'
                  'some instructions. An unprivileged attacker in a guest VM '
                  'could use this to\n'
                  'escalate privileges within the guest.'}
    }
]

broken_descriptions = [
    {
        'description': 
        """
Andy Lutomirski and Mika Penttilä discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555, CVE-2018-6556
        """,
        'cves': ['CVE-2018-10853', 'CVE-2018-6555', 'CVE-2018-6556'],
        'result': {'CVE-2018-10853': 'Andy Lutomirski and Mika Penttilä discovered that the KVM implementation in\nthe Linux kernel did not properly check privilege levels when emulating\nsome instructions. An unprivileged attacker in a guest VM could use this to\nescalate privileges within the guest.'},
        'error': "USN 1-1: CVE list is missing: 'It was discovered that a use-after-free vulnerability existed in the IRDA implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2018-6555, CVE-2018-6556'\n"
    },
    {
        'description': 
        """
Andy Lutomirski and Mika Penttilä discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853)

USN 3652-1 added a mitigation for Speculative Store Bypass
a.k.a. Spectre Variant 4 (CVE-2018-3639. This update provides the
corresponding mitigation for ARM64 processors. Please note that for
this mitigation to be effective, an updated firmware for the processor
may be required.
        """,
        'cves': ['CVE-2018-10853', 'CVE-2018-3639'],
        'result': {'CVE-2018-10853': 'Andy Lutomirski and Mika Penttilä discovered that the KVM implementation in\nthe Linux kernel did not properly check privilege levels when emulating\nsome instructions. An unprivileged attacker in a guest VM could use this to\nescalate privileges within the guest.'},
        'error': "USN 1-1: CVE list is missing: 'USN 3652-1 added a mitigation for Speculative Store Bypass a.k.a. Spectre Variant 4 (CVE-2018-3639. This update provides the corresponding mitigation for ARM64 processors. Please note that for this mitigation to be effective, an updated firmware for the processor may be required.'\n"
    }
]

class TestDescriptions:
    @pytest.mark.parametrize("usn", descriptions)
    @mock.patch("usn_lib.load_database")
    def test_descriptions(self, _load_database_mock, usn):
        _load_database_mock.return_value = []
        sync_from_usns = importlib.import_module("sync-from-usns")
        fake_usn = '1-1'
        db = {fake_usn: {'description': usn['description'], 'cves': usn['cves']}}
        result = sync_from_usns.extract_cve_descriptions(db[fake_usn], fake_usn, False)
        assert result == usn['result']

    @pytest.mark.parametrize("usn", broken_descriptions)
    @mock.patch("usn_lib.load_database")
    def test_descriptions_exception(self, _load_database_mock, usn, capsys):
        _load_database_mock.return_value = []
        sync_from_usns = importlib.import_module("sync-from-usns")
        fake_usn = '1-1'
        db = {fake_usn: {'description': usn['description'], 'cves': usn['cves']}}
        result = sync_from_usns.extract_cve_descriptions(db[fake_usn], fake_usn, True)
        captured = capsys.readouterr()
        assert result == usn['result']
        assert captured.err == usn['error']
