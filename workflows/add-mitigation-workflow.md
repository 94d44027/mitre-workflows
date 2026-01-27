# MITRE ATT&CK MITIGATION SYNCHRONIZATION WORKFLOW

## Purpose

Synchronize a MITRE ATT&CK mitigation and all its associated techniques/subtechniques from attack.mitre.org into the NebulaGraph database.

### When to Use This Workflow

When you receive a task like: "Sync mitigation M1033 to NebulaGraph" or "Process M1034 mitigation". The "M1034" (or any other mitigation following "MXXXX" pattern, where XXXX is 4 digits) will be an input parameter for this workflow further down abbreviated as M####. 


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
 
    rcelpe (bool, nullable, default: false) 
 > Note: "Can be applied to a host with critical vulnerability"
 
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

### STEP 1: Navigate to MITRE ATT&CK Page for mitigation M####
* Open MITRE ATT&CK mitigation page: https://attack.mitre.org/mitigations/M####/
> M#### stands for the mitigation being currently processed
* Take screenshot to see the page structure

### STEP 2: Extract Techniques List related to M####
* Locate the "Techniques Addressed by Mitigation" section
* Extract the COMPLETE list of technique/subtechnique IDs from the table
> CRITICAL: Use get_page_text or read_page tools to ensure you capture ALL techniques.
> CRITICAL: if the list looks like "T1557", ".002" it means that you have a technique "T1557" and its subtechnique "T1557.002"
> CRITICAL: both techniques and subtechniques are counted
* Indicate this list as MWMLIST
* Count the total number of techniques shown (verify against table header if present)

### STEP 3: Check if mitigation exists in the database
* switch to Nebula Graph Studio
* navigate to Console
* make sure you are in ESP01 space
* run the query like `MATCH (m:tMitreMitigation) WHERE id(m) IN ["M####"] RETURN id(m) AS mitigation;` where *"MXXXX"* is the input parameter for the workflow
* if the query output is not empty, proceed to step 4
* if the query output is empty, create an nGQL query like this `INSERT VERTEX IF NOT EXISTS tMitreMitigation(Mitigation_ID, Mitigation_Name, Matrix, Description, Mitigation_Version) VALUES "MXXXX":("MXXXX", "<Mitigation_Name>", "Enterprise", "<Brief_description>", "<Mitigation_Version>");` where MXXXX is the input parameter - mitigation ID, <Mitigation_name> - mitigation name, <Brief_description> - short description of the mitigation, <Mitigation_Version> - the version of the mitigation, if available on MITRE mitigation web page, leave empty if none available.
* Present the nGQL query for the user to approve
* Execute nGQl query for MXXXX tag creation after user approval
 

### STEP 4: Verify that techniques/subtechniques are present in the database
* switch to Nebula Graph Studio
* navigate to Console
* make sure you are in ESP01 space
* run the query like `MATCH (t:tMitreTechnique) WHERE id(t) IN ["TXXXX", "TYYY", "TZZZ.ZZZ"] RETURN id(t) AS technique;` where *"TXXXX", "TYYY", "TZZZ.ZZZ"* represent comma-delimited list of the techniques/subtechniques which presence is to be verified (MWMLIST)
* Memorize the techniques/subtechniques at the output window 
* check the number to the right of "Total" at the bottom right corner of query output window
* If this number is greater than 5, scroll down the window and memorize the remaining techniques/subtechniques in the output
* If there are multiple pages in the query output (the number in blue rounded square to the right of the "total" number") navigate to the next page until all lines in query output have been seen, understood and the resulting techniques and subtechniques have been memorized 
* Indicate the memorized list as DBMList
* Compare the MWMLIST to DBMLIST
* If there are techniques/subtechniques from MWMLIST which are not present in the database (DBMLIST), call this list IMISSTHEMLIST and go to the next step
* if there are no missing techniques/subtechniques (i.e. database contains every technique/subtechnique from the mitigation webpage)- proceed to step 6 

### STEP 5: Create missing techniques/subtechniques in the database
For each technique/subtechnique ID in the IMISSTHEMLIST:
* 5a. Navigate to technique page. URL format: https://attack.mitre.org/techniques/T####/ (or /T####/###/ for subtechniques)
* 5b. Extract required information:
    * Technique_ID (from URL or page)
    * Technique_Name (page heading)
    * Tactic_ID(s) - Look for "Tactics" section showing which tactic(s) this technique belongs to
    * Mitre_Attack_Version (from page metadata, use "18.0" if not found)
    * Domain (currently only "Enterprise")
> Note: For subtechniques identify parent technique ID, which is first 5 symbols like "TXXXX" before the dot (".") 
* 5c. Assign the tMireTechnique property values:
   * `rcelpe`: default to false (only set to true if explicitly mentioned regarding critical vulnerabilities)
   * `priority`: default to 4
   * `execution_min`: default to 0.1667
   * `execution_max`: default to 120
* 5d. Prepare nGQL expression to insert missing technique/subtechnique. Do not execute so far.
  * For parent technique:

text

`
INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) 
VALUES "T####":("T####", "Technique Name", "18.0", false, 4, 0.1667, 120);
`
  * For subtechnique:

text

`
INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) 
VALUES "T####.###":("T####.###", "Subtechnique Name", "18.0", false, 4, 0.1667, 120);
`
  * Insert tactic relationships (BOTH parent and subtechniques):

text

`
-- Parent technique to tactic
INSERT EDGE IF NOT EXISTS part_of VALUES "T####"->"TA####"@0:();
`

`
-- Subtechnique to tactic (same tactic as parent)
INSERT EDGE IF NOT EXISTS part_of VALUES "T####.###"->"TA####"@0:();
`
 * Insert parent-subtechnique hierarchy:

text

`
INSERT EDGE IF NOT EXISTS has_subtechnique VALUES "T####"->"T####.###"@0:();
`

5e. Process all the techniques/subtechniques in the IMISSTHEMLIST. Batch all the nGQL statements into the single text (indicate it as RESULTINSERT) separating them by new line and present it to the user for verification.
5f. Upon the user approval, execute RESULTINSERT

STEP 6: create mitigation edges

For each technique/subtechniaue from MWMLIST:

 * 6a. create nGQL statements for mitigates edges (can batch multiple):

text

`
INSERT EDGE IF NOT EXISTS mitigates 
VALUES "M####"->"T####"@0:(NULL, "Enterprise"),
       "M####"->"T####.###"@0:(NULL, "Enterprise");
`

* 6b. get all the statements into the single text (indicate it as RESULTINSERT2) separating them by new line and present it to the user for verification.
* 6c. Upon the user approval, execute RESULTINSERT2

STEP 7: Verification
* 7a. Count check:

text

`
MATCH (m:tMitreMitigation)-[e:mitigates]->(t) WHERE id(m) == "M####" RETURN COUNT(e);
`

Compare result with the total count from MITRE ATT&CK page (MWMLIST).

* 7b. If counts don't match:

  * List all techniques in the database vs. MITRE ATT&CK (MWMLIST)
  * Identify missing techniques

STEP 8: STOP
Once verification passes, STOP. Do not proceed with other investigations unless explicitly requested.
Present the results.
