import os
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from google.api_core import exceptions as gcp_exceptions
from google.cloud import modelarmor_v1 as ma
from pydantic import BaseModel

from demo_scenarios import SCENARIOS

load_dotenv()

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
REGION = os.environ.get("GCP_REGION", "us-central1")
TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "demo-template")
PORT = int(os.environ.get("PORT", "5610"))

API_ENDPOINT = f"modelarmor.{REGION}.rep.googleapis.com"
PARENT = f"projects/{PROJECT_ID}/locations/{REGION}"
TEMPLATE_NAME = f"{PARENT}/templates/{TEMPLATE_ID}"
DLP_INSPECT_TEMPLATE = os.environ.get(
    "DLP_INSPECT_TEMPLATE",
    f"{PARENT}/inspectTemplates/model-armor-inspect",
)

app = FastAPI(title="Model Armor Demo")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def get_client() -> ma.ModelArmorClient:
    return ma.ModelArmorClient(
        client_options={"api_endpoint": API_ENDPOINT}
    )


def build_default_template() -> ma.Template:
    confidence = ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE
    return ma.Template(
        filter_config=ma.FilterConfig(
            pi_and_jailbreak_filter_settings=ma.PiAndJailbreakFilterSettings(
                filter_enforcement=1,  # ENABLED
                confidence_level=confidence,
            ),
            malicious_uri_filter_settings=ma.MaliciousUriFilterSettings(
                filter_enforcement=1,  # ENABLED
            ),
            rai_settings=ma.RaiFilterSettings(
                rai_filters=[
                    ma.RaiFilterSettings.RaiFilter(
                        filter_type=ma.RaiFilterType.HATE_SPEECH,
                        confidence_level=confidence,
                    ),
                    ma.RaiFilterSettings.RaiFilter(
                        filter_type=ma.RaiFilterType.HARASSMENT,
                        confidence_level=confidence,
                    ),
                    ma.RaiFilterSettings.RaiFilter(
                        filter_type=ma.RaiFilterType.SEXUALLY_EXPLICIT,
                        confidence_level=confidence,
                    ),
                    ma.RaiFilterSettings.RaiFilter(
                        filter_type=ma.RaiFilterType.DANGEROUS,
                        confidence_level=confidence,
                    ),
                ]
            ),
            sdp_settings=ma.SdpFilterSettings(
                advanced_config=ma.SdpAdvancedConfig(
                    inspect_template=DLP_INSPECT_TEMPLATE,
                ),
            ),
        )
    )


def template_to_dict(template: ma.Template) -> dict:
    fc = template.filter_config
    pi = fc.pi_and_jailbreak_filter_settings
    uri = fc.malicious_uri_filter_settings
    rai = fc.rai_settings
    sdp = fc.sdp_settings

    return {
        "name": template.name,
        "pi_and_jailbreak": {
            "enabled": pi.filter_enforcement == 1,
            "confidence_level": ma.DetectionConfidenceLevel(pi.confidence_level).name,
        },
        "malicious_uri": {
            "enabled": uri.filter_enforcement == 1,
        },
        "rai_filters": [
            {
                "type": ma.RaiFilterType(f.filter_type).name,
                "confidence_level": ma.DetectionConfidenceLevel(f.confidence_level).name,
            }
            for f in rai.rai_filters
        ],
        "sdp": {
            "advanced_enabled": bool(sdp.advanced_config.inspect_template) if sdp.advanced_config else False,
            "inspect_template": sdp.advanced_config.inspect_template if sdp.advanced_config else None,
        },
    }


def parse_sanitization_result(result: ma.SanitizationResult) -> dict:
    # filter_results is a map: {"pi_and_jailbreak": FilterResult, "rai": FilterResult, ...}
    fr_map = result.filter_results

    def execution_info(state, match, messages=None):
        info = {
            "executed": state == ma.FilterExecutionState.EXECUTION_SUCCESS,
            "matched": match == ma.FilterMatchState.MATCH_FOUND,
        }
        if messages:
            info["messages"] = [m.message for m in messages]
        return info

    output = {
        "overall_match": ma.FilterMatchState(result.filter_match_state).name,
        "invocation_result": ma.InvocationResult(result.invocation_result).name,
        "filters": {},
    }

    # PI & Jailbreak
    if "pi_and_jailbreak" in fr_map:
        pi = fr_map["pi_and_jailbreak"].pi_and_jailbreak_filter_result
        pi_info = execution_info(pi.execution_state, pi.match_state, pi.message_items)
        if pi.confidence_level:
            pi_info["confidence_level"] = ma.DetectionConfidenceLevel(pi.confidence_level).name
        output["filters"]["pi_and_jailbreak"] = pi_info

    # RAI
    if "rai" in fr_map:
        rai = fr_map["rai"].rai_filter_result
        rai_info = execution_info(rai.execution_state, rai.match_state, rai.message_items)
        rai_info["categories"] = {}
        if rai.rai_filter_type_results:
            for type_key, type_result in rai.rai_filter_type_results.items():
                rai_info["categories"][type_key] = {
                    "matched": type_result.match_state == ma.FilterMatchState.MATCH_FOUND,
                    "confidence_level": ma.DetectionConfidenceLevel(type_result.confidence_level).name
                    if type_result.confidence_level
                    else "NONE",
                }
        output["filters"]["rai"] = rai_info

    # SDP
    if "sdp" in fr_map:
        sdp = fr_map["sdp"].sdp_filter_result
        sdp_info = {"inspect": None, "deidentify": None}
        if sdp.inspect_result:
            ir = sdp.inspect_result
            sdp_info["inspect"] = {
                "executed": ir.execution_state == ma.FilterExecutionState.EXECUTION_SUCCESS,
                "matched": ir.match_state == ma.FilterMatchState.MATCH_FOUND,
                "findings": [
                    {
                        "info_type": f.info_type,
                        "likelihood": ma.SdpFindingLikelihood(f.likelihood).name if f.likelihood else "UNKNOWN",
                    }
                    for f in (ir.findings or [])
                ],
            }
        if sdp.deidentify_result:
            dr = sdp.deidentify_result
            sdp_info["deidentify"] = {
                "executed": dr.execution_state == ma.FilterExecutionState.EXECUTION_SUCCESS,
                "matched": dr.match_state == ma.FilterMatchState.MATCH_FOUND,
            }
        output["filters"]["sdp"] = sdp_info

    # Malicious URI
    if "malicious_uris" in fr_map:
        uri = fr_map["malicious_uris"].malicious_uri_filter_result
        uri_info = execution_info(uri.execution_state, uri.match_state, uri.message_items)
        if uri.malicious_uri_matched_items:
            uri_info["matched_uris"] = [item.uri for item in uri.malicious_uri_matched_items]
        output["filters"]["malicious_uri"] = uri_info

    # CSAM
    if "csam" in fr_map:
        csam = fr_map["csam"].csam_filter_filter_result
        output["filters"]["csam"] = execution_info(csam.execution_state, csam.match_state, csam.message_items)

    return output


# --- Pydantic models ---

class SanitizeRequest(BaseModel):
    text: str


class TemplateConfig(BaseModel):
    pi_confidence: str = "MEDIUM_AND_ABOVE"
    rai_confidence: str = "MEDIUM_AND_ABOVE"
    malicious_uri_enabled: bool = True
    sdp_enabled: bool = True
    pi_enabled: bool = True


# --- Endpoints ---

@app.get("/")
async def serve_frontend():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.post("/api/setup")
async def setup_template():
    client = get_client()
    template = build_default_template()
    try:
        created = client.create_template(
            request=ma.CreateTemplateRequest(
                parent=PARENT,
                template_id=TEMPLATE_ID,
                template=template,
            )
        )
        return {"status": "created", "template": template_to_dict(created)}
    except gcp_exceptions.AlreadyExists:
        existing = client.get_template(
            request=ma.GetTemplateRequest(name=TEMPLATE_NAME)
        )
        return {"status": "already_exists", "template": template_to_dict(existing)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/template")
async def get_template():
    client = get_client()
    try:
        template = client.get_template(
            request=ma.GetTemplateRequest(name=TEMPLATE_NAME)
        )
        return template_to_dict(template)
    except gcp_exceptions.NotFound:
        raise HTTPException(status_code=404, detail="Template not found. Call POST /api/setup first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/setup-custom")
async def setup_custom_template(config: TemplateConfig):
    client = get_client()

    confidence_map = {
        "LOW_AND_ABOVE": ma.DetectionConfidenceLevel.LOW_AND_ABOVE,
        "MEDIUM_AND_ABOVE": ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE,
        "HIGH": ma.DetectionConfidenceLevel.HIGH,
    }
    pi_conf = confidence_map.get(config.pi_confidence, ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE)
    rai_conf = confidence_map.get(config.rai_confidence, ma.DetectionConfidenceLevel.MEDIUM_AND_ABOVE)

    template = ma.Template(
        filter_config=ma.FilterConfig(
            pi_and_jailbreak_filter_settings=ma.PiAndJailbreakFilterSettings(
                filter_enforcement=1 if config.pi_enabled else 2,
                confidence_level=pi_conf,
            ),
            malicious_uri_filter_settings=ma.MaliciousUriFilterSettings(
                filter_enforcement=1 if config.malicious_uri_enabled else 2,
            ),
            rai_settings=ma.RaiFilterSettings(
                rai_filters=[
                    ma.RaiFilterSettings.RaiFilter(filter_type=t, confidence_level=rai_conf)
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
                ) if config.sdp_enabled else None,
            ),
        )
    )

    try:
        # Delete existing and recreate
        try:
            client.delete_template(request=ma.DeleteTemplateRequest(name=TEMPLATE_NAME))
        except gcp_exceptions.NotFound:
            pass

        created = client.create_template(
            request=ma.CreateTemplateRequest(
                parent=PARENT,
                template_id=TEMPLATE_ID,
                template=template,
            )
        )
        return {"status": "created", "template": template_to_dict(created)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sanitize-prompt")
async def sanitize_prompt(req: SanitizeRequest):
    client = get_client()
    start = time.time()
    try:
        response = client.sanitize_user_prompt(
            request=ma.SanitizeUserPromptRequest(
                name=TEMPLATE_NAME,
                user_prompt_data=ma.DataItem(text=req.text),
            )
        )
        elapsed_ms = round((time.time() - start) * 1000)
        result = parse_sanitization_result(response.sanitization_result)
        result["elapsed_ms"] = elapsed_ms
        result["mode"] = "prompt"
        return result
    except gcp_exceptions.NotFound:
        raise HTTPException(status_code=404, detail="Template not found. Call POST /api/setup first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/sanitize-response")
async def sanitize_response(req: SanitizeRequest):
    client = get_client()
    start = time.time()
    try:
        response = client.sanitize_model_response(
            request=ma.SanitizeModelResponseRequest(
                name=TEMPLATE_NAME,
                model_response_data=ma.DataItem(text=req.text),
            )
        )
        elapsed_ms = round((time.time() - start) * 1000)
        result = parse_sanitization_result(response.sanitization_result)
        result["elapsed_ms"] = elapsed_ms
        result["mode"] = "response"
        return result
    except gcp_exceptions.NotFound:
        raise HTTPException(status_code=404, detail="Template not found. Call POST /api/setup first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scenarios")
async def get_scenarios():
    return SCENARIOS


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
