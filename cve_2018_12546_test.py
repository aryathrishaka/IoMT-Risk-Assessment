# ---------------------------------------------------------
# CVE-2018-12546 Controlled Validation Case
# ---------------------------------------------------------
# CVE-specific validation record for the Mosquitto 1.5.5
# laboratory experiment.
#
# The actual experiment was performed manually in the
# isolated laboratory environment.
# This module records and structures its result.
# ---------------------------------------------------------

from attack_simulation import (
    run_controlled_validation,
    print_validation_result
)


def validate_cve_2018_12546():
    """
    Record the controlled validation performed for
    CVE-2018-12546.
    """

    result = run_controlled_validation(

    cve_id="CVE-2018-12546",

    target="Eclipse Mosquitto 1.5.5",

    affected_component="Mosquitto",

    prerequisites=[
        "retained_messages_enabled",
        "acl_enabled",
        "authenticated MQTT client"
    ],

        validation_procedure=(
            "Publish an authenticated retained MQTT message, "
            "change the publisher's ACL so write access is "
            "revoked, then connect a new subscriber and "
            "observe whether the retained message is delivered."
        ),

        validation_status="VALIDATED",

        evidence=[
            "Retained message: Temperature=36.8",
            "Publisher write access was changed",
            "New subscriber received the retained message",
            "Broker log recorded retained-message delivery"
        ],

        impact=[
            "A previously published retained message "
            "remained accessible after the publisher's "
            "access was changed",
            "The experiment demonstrated the documented "
            "retained-message access-control behavior"
        ]
    )

    return result


# ---------------------------------------------------------
# Standalone test
# ---------------------------------------------------------

if __name__ == "__main__":

    validation_result = validate_cve_2018_12546()

    print_validation_result(
        validation_result
    )