"""Create (or verify) the Model Armor demo template and DLP inspect template."""

import os
import sys

from dotenv import load_dotenv
from google.api_core import exceptions as gcp_exceptions
from google.cloud import modelarmor_v1 as ma

load_dotenv()

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
REGION = os.environ.get("GCP_REGION", "us-central1")
TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "demo-template")

if not PROJECT_ID:
    print("Error: GCP_PROJECT_ID not set. Copy .env.example to .env and fill it in.")
    sys.exit(1)

API_ENDPOINT = f"modelarmor.{REGION}.rep.googleapis.com"
PARENT = f"projects/{PROJECT_ID}/locations/{REGION}"
TEMPLATE_NAME = f"{PARENT}/templates/{TEMPLATE_ID}"
DLP_INSPECT_TEMPLATE = f"{PARENT}/inspectTemplates/model-armor-inspect"

CONFIDENCE = ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE

DLP_INFO_TYPES = [
    # Australian PII
    "AUSTRALIA_TAX_FILE_NUMBER",
    "AUSTRALIA_MEDICARE_NUMBER",
    "AUSTRALIA_DRIVERS_LICENSE_NUMBER",
    "AUSTRALIA_PASSPORT",
    # Universal PII
    "CREDIT_CARD_NUMBER",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON_NAME",
    "STREET_ADDRESS",
    "IP_ADDRESS",
    # Credentials
    "GCP_API_KEY",
    "AUTH_TOKEN",
    "AWS_CREDENTIALS",
    "PASSPORT",
]


def setup_dlp_template():
    """Create the Sensitive Data Protection inspect template for PII detection."""
    import google.cloud.dlp_v2 as dlp

    client = dlp.DlpServiceClient()
    inspect_config = dlp.InspectConfig(
        info_types=[dlp.InfoType(name=t) for t in DLP_INFO_TYPES],
        min_likelihood=dlp.Likelihood.POSSIBLE,
    )

    try:
        template = client.create_inspect_template(
            request=dlp.CreateInspectTemplateRequest(
                parent=PARENT,
                inspect_template=dlp.InspectTemplate(
                    display_name="Model Armor Demo PII Detection",
                    description="Detects Australian and universal PII and credentials",
                    inspect_config=inspect_config,
                ),
                template_id="model-armor-inspect",
            )
        )
        print(f"DLP inspect template created: {template.name}")
    except (gcp_exceptions.AlreadyExists, gcp_exceptions.InvalidArgument):
        print(f"DLP inspect template already exists: {DLP_INSPECT_TEMPLATE}")
    except (gcp_exceptions.PermissionDenied, gcp_exceptions.Forbidden) as e:
        print(f"Failed to create DLP template. Make sure the DLP API is enabled:\n")
        print(f"  gcloud services enable dlp.googleapis.com --project={PROJECT_ID}\n")
        print(f"Error: {e}")
        sys.exit(1)


def build_template() -> ma.Template:
    return ma.Template(
        filter_config=ma.FilterConfig(
            pi_and_jailbreak_filter_settings=ma.PiAndJailbreakFilterSettings(
                filter_enforcement=1,  # ENABLED
                confidence_level=CONFIDENCE,
            ),
            malicious_uri_filter_settings=ma.MaliciousUriFilterSettings(
                filter_enforcement=1,  # ENABLED
            ),
            rai_settings=ma.RaiFilterSettings(
                rai_filters=[
                    ma.RaiFilterSettings.RaiFilter(
                        filter_type=t, confidence_level=CONFIDENCE
                    )
                    for t in [
                        ma.RaiFilterType.HATE_SPEECH,
                        ma.RaiFilterType.HARASSMENT,
                        ma.RaiFilterType.SEXUALLY_EXPLICIT,
                        ma.RaiFilterType.DANGEROUS,
                    ]
                ]
            ),
            sdp_settings=ma.SdpFilterSettings(
                advanced_config=ma.SdpAdvancedConfig(
                    inspect_template=DLP_INSPECT_TEMPLATE,
                ),
            ),
        )
    )


def main():
    print(f"Project:  {PROJECT_ID}")
    print(f"Region:   {REGION}")
    print(f"Template: {TEMPLATE_ID}")
    print(f"Endpoint: {API_ENDPOINT}")
    print()

    # Step 1: Create DLP inspect template
    print("--- DLP Inspect Template ---")
    setup_dlp_template()
    print()

    # Step 2: Create Model Armor template
    print("--- Model Armor Template ---")
    client = ma.ModelArmorClient(
        client_options={"api_endpoint": API_ENDPOINT}
    )

    try:
        template = client.create_template(
            request=ma.CreateTemplateRequest(
                parent=PARENT,
                template_id=TEMPLATE_ID,
                template=build_template(),
            )
        )
        print(f"Template created: {template.name}")
    except gcp_exceptions.AlreadyExists:
        template = client.get_template(
            request=ma.GetTemplateRequest(name=TEMPLATE_NAME)
        )
        print(f"Template already exists: {template.name}")
    except (gcp_exceptions.PermissionDenied, gcp_exceptions.Forbidden) as e:
        print(f"Permission denied. Make sure you have run:\n")
        print(f"  gcloud auth application-default login")
        print(f"  gcloud services enable modelarmor.googleapis.com --project={PROJECT_ID}\n")
        print(f"Error: {e}")
        sys.exit(1)

    fc = template.filter_config
    print()
    print("Filters enabled:")
    print(f"  PI & Jailbreak:    ENABLED, {ma.DetectionConfidenceLevel(fc.pi_and_jailbreak_filter_settings.confidence_level).name}")
    print(f"  Malicious URI:     ENABLED")
    sdp = fc.sdp_settings
    if sdp.advanced_config and sdp.advanced_config.inspect_template:
        print(f"  Sensitive Data:    ADVANCED (DLP)")
        print(f"    Inspect template: {sdp.advanced_config.inspect_template}")
    else:
        print(f"  Sensitive Data:    BASIC")
    for rf in fc.rai_settings.rai_filters:
        name = ma.RaiFilterType(rf.filter_type).name
        conf = ma.DetectionConfidenceLevel(rf.confidence_level).name
        print(f"  RAI {name}: {conf}")
    print()
    print("Ready. Run the demo with: python3 server.py")


if __name__ == "__main__":
    main()
