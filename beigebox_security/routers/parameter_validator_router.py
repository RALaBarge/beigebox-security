"""MCP Parameter Validation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from beigebox_security.integrations.parameters import (
    ParameterValidator,
    TOOL_RULES,
)

router = APIRouter()

# Singleton validator instance
_validator = ParameterValidator()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ValidateParametersRequest(BaseModel):
    """Request to validate tool parameters."""

    tool_name: str = Field(..., description="Name of the tool (e.g., workspace_file, network_audit, cdp)")
    parameters: dict = Field(..., description="Tool parameters to validate")
    allow_unsafe: bool = Field(False, description="Allow parameters that are risky but not strictly forbidden")


class ValidationIssueResponse(BaseModel):
    """A single validation issue."""

    tier: str = Field(..., description="Validation tier: schema, constraint, semantic, isolation")
    severity: str = Field(..., description="critical, high, medium, low")
    tool: str = Field(..., description="Tool name")
    field: str = Field(..., description="Parameter field name")
    message: str = Field(..., description="Description of the issue")
    attack_type: str = Field(..., description="Attack category")
    remediation: str = Field("", description="Remediation hint")


class ValidateParametersResponse(BaseModel):
    """Response from parameter validation."""

    valid: bool = Field(..., description="Whether parameters passed validation")
    issues: list[ValidationIssueResponse] = Field(default_factory=list, description="List of validation issues found")
    sanitized_parameters: dict = Field(default_factory=dict, description="Cleaned parameters (if valid=True)")
    elapsed_ms: float = Field(0.0, description="Validation time in milliseconds")


class BatchValidateRequest(BaseModel):
    """Batch validation request."""

    requests: list[ValidateParametersRequest]


class BatchValidateResponse(BaseModel):
    """Batch validation response."""

    results: list[ValidateParametersResponse]
    total: int
    valid_count: int
    invalid_count: int


class ToolRulesResponse(BaseModel):
    """Validation rules for a tool."""

    tool: str
    description: str
    tiers: list[str]
    parameters: dict
    attack_vectors: list[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/validate", response_model=ValidateParametersResponse)
async def validate_parameters(request: ValidateParametersRequest):
    """
    Validate tool parameters for security issues.

    Checks for path traversal, injection, SSRF, ReDoS, and other attacks
    across 4 validation tiers: schema, constraint, semantic, isolation.
    """
    result = _validator.validate(
        tool_name=request.tool_name,
        params=request.parameters,
        allow_unsafe=request.allow_unsafe,
    )

    return ValidateParametersResponse(
        valid=result.valid,
        issues=[
            ValidationIssueResponse(
                tier=i.tier,
                severity=i.severity,
                tool=i.tool,
                field=i.field,
                message=i.message,
                attack_type=i.attack_type,
                remediation=i.remediation,
            )
            for i in result.issues
        ],
        sanitized_parameters=result.sanitized_params,
        elapsed_ms=result.elapsed_ms,
    )


@router.post("/validate-batch", response_model=BatchValidateResponse)
async def validate_batch(request: BatchValidateRequest):
    """
    Validate multiple tool parameter sets in batch.

    Returns individual results plus aggregate counts.
    """
    calls = [
        {
            "tool_name": r.tool_name,
            "parameters": r.parameters,
            "allow_unsafe": r.allow_unsafe,
        }
        for r in request.requests
    ]

    raw_results = _validator.validate_batch(calls)

    results = []
    valid_count = 0
    for raw in raw_results:
        resp = ValidateParametersResponse(
            valid=raw.valid,
            issues=[
                ValidationIssueResponse(
                    tier=i.tier,
                    severity=i.severity,
                    tool=i.tool,
                    field=i.field,
                    message=i.message,
                    attack_type=i.attack_type,
                    remediation=i.remediation,
                )
                for i in raw.issues
            ],
            sanitized_parameters=raw.sanitized_params,
            elapsed_ms=raw.elapsed_ms,
        )
        results.append(resp)
        if raw.valid:
            valid_count += 1

    return BatchValidateResponse(
        results=results,
        total=len(results),
        valid_count=valid_count,
        invalid_count=len(results) - valid_count,
    )


@router.get("/rules/{tool_name}", response_model=ToolRulesResponse)
async def get_validation_rules(tool_name: str):
    """
    Get validation rules for a specific tool.

    Returns the parameter schema, validation tiers, and known attack vectors.
    """
    rules = _validator.get_rules(tool_name)
    if rules is None:
        raise HTTPException(
            status_code=404,
            detail=f"No validation rules for tool '{tool_name}'. "
            f"Supported tools: {_validator.supported_tools}",
        )

    return ToolRulesResponse(**rules)
