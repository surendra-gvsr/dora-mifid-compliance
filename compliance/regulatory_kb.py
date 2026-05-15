from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RegulatoryArticle:
    id: str                      # "DORA-Art.9"
    regulation: str              # "DORA" | "MIFID_II"
    article_number: str          # "Art.9"
    title: str
    text_excerpt: str
    requirements: List[str]
    cross_references: List[str]


DORA_KB: Dict[str, RegulatoryArticle] = {
    "Art.5": RegulatoryArticle(
        id="DORA-Art.5",
        regulation="DORA",
        article_number="Art.5",
        title="ICT Risk Management Framework",
        text_excerpt=(
            "Financial entities shall have in place a sound, comprehensive and "
            "well-documented ICT risk management framework as part of their overall "
            "risk management system that enables them to address ICT risk quickly, "
            "efficiently and comprehensively and to ensure a high level of digital "
            "operational resilience."
        ),
        requirements=[
            "Establish a documented ICT risk management framework",
            "Identify, classify, and document ICT assets",
            "Continuously monitor and assess ICT risks",
            "Review and update the framework at least annually",
            "Board-level accountability for ICT risk governance",
        ],
        cross_references=["Art.6", "Art.9", "Art.11", "Art.17"],
    ),
    "Art.6": RegulatoryArticle(
        id="DORA-Art.6",
        regulation="DORA",
        article_number="Art.6",
        title="ICT Systems, Protocols and Tools",
        text_excerpt=(
            "Financial entities shall use and maintain updated ICT systems, protocols "
            "and tools that are appropriate to the magnitude of operations supporting "
            "the conduct of their activities, reliable, have sufficient capacity, and "
            "are technologically resilient to adequately deal with additional information "
            "processing needs."
        ),
        requirements=[
            "Maintain an up-to-date inventory of ICT assets",
            "Ensure systems meet availability and capacity SLAs",
            "Apply timely security patches and updates",
            "Monitor system performance and resilience continuously",
        ],
        cross_references=["Art.5", "Art.9"],
    ),
    "Art.7": RegulatoryArticle(
        id="DORA-Art.7",
        regulation="DORA",
        article_number="Art.7",
        title="ICT Third-Party Risk Management",
        text_excerpt=(
            "Financial entities shall manage ICT third-party risk as an integral component "
            "of ICT risk within their ICT risk management framework, and in accordance with "
            "the following principles: ICT third-party risk is appropriately identified, "
            "assessed, monitored, and managed within the financial entity."
        ),
        requirements=[
            "Conduct due-diligence assessments on all critical ICT third parties",
            "Maintain a register of ICT third-party arrangements",
            "Include contractual provisions for audit rights and exit strategies",
            "Monitor and report on concentration risk from ICT providers",
            "Define and test exit plans for critical third-party dependencies",
        ],
        cross_references=["Art.5", "Art.11"],
    ),
    "Art.9": RegulatoryArticle(
        id="DORA-Art.9",
        regulation="DORA",
        article_number="Art.9",
        title="Protection and Prevention",
        text_excerpt=(
            "Financial entities shall continuously monitor and control the security and "
            "functioning of ICT systems and tools. Financial entities shall minimise the "
            "impact of ICT risk by deploying appropriate ICT security tools, policies, "
            "and procedures. Financial entities shall have in place mechanisms to promptly "
            "detect anomalous activities."
        ),
        requirements=[
            "Deploy encryption for data at rest and in transit",
            "Implement network segmentation and access controls",
            "Enforce multi-factor authentication for privileged accounts",
            "Maintain a vulnerability management programme with defined SLAs",
            "Operate real-time anomaly detection and alerting capabilities",
            "Document a DDoS response runbook",
        ],
        cross_references=["Art.5", "Art.6", "Art.17"],
    ),
    "Art.11": RegulatoryArticle(
        id="DORA-Art.11",
        regulation="DORA",
        article_number="Art.11",
        title="Business Continuity and Disaster Recovery",
        text_excerpt=(
            "Financial entities shall put in place a comprehensive ICT business continuity "
            "policy which may be adopted as a dedicated specific policy, forming an integral "
            "part of the overall business continuity policy of the financial entity. Financial "
            "entities shall implement ICT business continuity plans enabling financial entities "
            "to respond to all ICT-related incidents, and in particular cyber-attacks."
        ),
        requirements=[
            "Maintain documented BCP/DR plans for all critical ICT systems",
            "Define and test RTO and RPO targets annually",
            "Conduct crisis communication exercises",
            "Ensure BCP covers third-party dependency failure scenarios",
        ],
        cross_references=["Art.5", "Art.7", "Art.17"],
    ),
    "Art.17": RegulatoryArticle(
        id="DORA-Art.17",
        regulation="DORA",
        article_number="Art.17",
        title="ICT-Related Incident Management Process",
        text_excerpt=(
            "Financial entities shall define, establish and implement an ICT-related incident "
            "management process to detect, manage, and notify ICT-related incidents, and shall "
            "classify ICT-related incidents and determine their impact on the basis of criteria "
            "set out in Article 18(1)."
        ),
        requirements=[
            "Define an incident classification scheme with severity tiers",
            "Establish escalation paths and notification timelines",
            "Report major ICT incidents to the competent authority within prescribed deadlines",
            "Conduct root-cause analysis and post-incident reviews",
            "Maintain an incident register with outcomes and lessons learned",
        ],
        cross_references=["Art.5", "Art.9", "Art.11"],
    ),
}

MIFID_II_KB: Dict[str, RegulatoryArticle] = {
    "Art.16": RegulatoryArticle(
        id="MIFID2-Art.16",
        regulation="MIFID_II",
        article_number="Art.16",
        title="Organisational Requirements",
        text_excerpt=(
            "An investment firm shall have robust governance arrangements, which include "
            "a clear organisational structure with well-defined, transparent and consistent "
            "lines of responsibility, effective processes for identifying, managing, "
            "monitoring and reporting the risks it is or might be exposed to, and adequate "
            "internal control mechanisms, including sound administrative and accounting "
            "procedures and effective control and safeguard arrangements for information "
            "processing systems."
        ),
        requirements=[
            "Maintain adequate ICT infrastructure supporting all business activities",
            "Implement effective ICT risk identification and monitoring controls",
            "Ensure business continuity arrangements cover ICT disruption scenarios",
            "Document organisational structure and lines of ICT responsibility",
            "Establish safeguard arrangements for information processing systems",
        ],
        cross_references=["DORA-Art.5", "DORA-Art.7", "DORA-Art.9"],
    ),
}


def _normalise(article_id: str) -> str:
    s = article_id.strip()
    if not s.startswith("Art."):
        s = f"Art.{s}"
    return s


def get_dora_article(article_id: str) -> Optional[RegulatoryArticle]:
    return DORA_KB.get(_normalise(article_id))


def get_mifid_article(article_id: str) -> Optional[RegulatoryArticle]:
    return MIFID_II_KB.get(_normalise(article_id))


def get_all_articles(regulation: str = "ALL") -> List[RegulatoryArticle]:
    if regulation == "DORA":
        return list(DORA_KB.values())
    if regulation in ("MIFID_II", "MIFID2"):
        return list(MIFID_II_KB.values())
    return list(DORA_KB.values()) + list(MIFID_II_KB.values())
