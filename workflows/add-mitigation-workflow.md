# MITRE ATT&CK MITIGATION SYNCHRONIZATION WORKFLOW

## Purpose

Synchronize a MITRE ATT&CK mitigation and all its associated techniques/subtechniques from attack.mitre.org into the NebulaGraph database.

### When to Use This Workflow

When you receive a task like: "Sync mitigation M1033 to NebulaGraph" or "Process M1034 mitigation"


## Critical Schema Information


### Tag: tMitreMitigation

*Properties:* 
 
 Mitigation_ID (string, nullable)
 
 Mitigation_Name (string, nullable)
 
 Matrix (string, nullable, default: "Enterprise")
 
 Description (string, nullable)
 
 Mitigation_Version (string, nullable)


### Tag: tMitreTechnique

*Properties:*

 Technique_ID (string, NOT NULL)

 Technique_Name (string, NOT NULL)
 
 Mitre_Attack_Version (string, nullable)
 
 rcelpe (bool, nullable, default: false) - "Can be applied to a host with critical vulnerability"
 
 priority (int8, NOT NULL, default: 4)
 
 execution_min (float, NOT NULL, default: 0.1667)
 
 execution_max (float, NOT NULL, default: 120)

> Note: newly added techniques should have Mitre_Attack_Version = "18.0" 

### Tag: tMitreTactic

*Properties*

 Tactic_ID (string, NOT NULL)
 
 Tactic_Name (string, NOT NULL)
 
 Mitre_Attack_Version (string, nullable)

### Edge: mitigates (from tMitreMitigation to tMitreTechnique)

*Properties*

 Use_Description (string, nullable)
 
 Domain (string, nullable, default: "Enterprise")

 > Note: added edges should have rank @0

### Edge: part_of (from technique/subtechnique to tactic)
 
 No properties

 > CRITICAL: Both parent techniques AND subtechniques connect directly to tactics.
 > Note: added edges should have rank @0 .
 > Example: T1071.001 -> TA0011, T1071 -> TA0011 (both connect to same tactic).
 
### Edge: has_subtechnique 
 
 No properties
 
> From parent technique to subtechnique.
> This edge represents the technique hierarchy.
> Example: T1071 -> T1071.001 (parent has subtechnique).
> Note: Added edges should have rank @0

## Workflow Steps

### STEP 1: Navigate to MITRE ATT&CK Page
* Open MITRE ATT&CK mitigation page: https://attack.mitre.org/mitigations/M####/
> M#### stands for the mitigation being currently processed
* Take screenshot to see the page structure

### STEP 2: Extract Technique List
* Locate the "Techniques Addressed by Mitigation" section
* Extract the COMPLETE list of technique IDs from the table
> CRITICAL: Use get_page_text or read_page tools to ensure you capture ALL techniques
* Count the total number of techniques shown (verify against table header if present)

### STEP 3: For EACH Technique - Open and Extract Details

For each technique ID in the list:

* 3a. Navigate to technique page. URL format: https://attack.mitre.org/techniques/T####/ (or /T####/###/ for subtechniques)

* 3b. Extract required information:

  * Technique_ID (from URL or page)

  * Technique_Name (page heading)

*** Tactic_ID(s) - Look for "Tactics" section showing which tactic(s) this technique belongs to

*** Mitre_Attack_Version (from page metadata, use "18.0" if not found)

*** Domain (currently only "Enterprise")

*** For subtechniques: identify parent technique ID

** 3c. Determine property values:

*** rcelpe: default to false (only set to true if explicitly mentioned regarding critical vulnerabilities)

*** priority: default to 4

*** execution_min: default to 0.1667

*** execution_max: default to 120

STEP 4: Insert Data into NebulaGraph
4a. For each parent technique:

text
INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) 
VALUES "T####":("T####", "Technique Name", "18.0", false, 4, 0.1667, 120);
4b. For each subtechnique:

text
INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) 
VALUES "T####.###":("T####.###", "Subtechnique Name", "18.0", false, 4, 0.1667, 120);
4c. Insert tactic relationships (BOTH parent and subtechniques):

text
-- Parent technique to tactic
INSERT EDGE IF NOT EXISTS part_of VALUES "T####"->"TA####"@0:();

-- Subtechnique to tactic (same tactic as parent)
INSERT EDGE IF NOT EXISTS part_of VALUES "T####.###"->"TA####"@0:();
4d. Insert parent-subtechnique hierarchy:

text
INSERT EDGE IF NOT EXISTS has_subtechnique VALUES "T####"->"T####.###"@0:();
4e. Insert mitigates edges (can batch multiple):

text
INSERT EDGE IF NOT EXISTS mitigates 
VALUES "M####"->"T####"@0:(NULL, "Enterprise"),
       "M####"->"T####.###"@0:(NULL, "Enterprise");
STEP 5: Verification
5a. Count check:

text
MATCH (m:tMitreMitigation)-[e:mitigates]->(t) WHERE id(m) == "M####" RETURN COUNT(e);
Compare result with the total count from MITRE ATT&CK page.

5b. If counts don't match:

List all techniques in graph vs. MITRE ATT&CK

Identify missing techniques

Insert missing data

STEP 6: STOP
Once verification passes, STOP. Do not proceed with other investigations unless explicitly requested.
