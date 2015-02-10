# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

# risks from classes.dex :
    # API <-> Permissions 
        # method X is more dangerous than another one
    # const-string -> apk-tool
        # v0 <- X
        # v1 <- Y

        # v10 <- X
        # v11 <- Y

        # CALL( v0, v1 )
    # obfuscated names

GENERAL_RISK            = 0
DANGEROUS_RISK          = 1
SIGNATURE_SYSTEM_RISK   = 2 
SIGNATURE_RISK          = 3
NORMAL_RISK             = 4

MONEY_RISK              = 5 
SMS_RISK                = 6
PHONE_RISK              = 7
INTERNET_RISK           = 8
PRIVACY_RISK            = 9 
DYNAMIC_RISK            = 10

BINARY_RISK             = 11
EXPLOIT_RISK            = 12

RISK_VALUES = {
    DANGEROUS_RISK          : 5,
    SIGNATURE_SYSTEM_RISK   : 10,
    SIGNATURE_RISK          : 10,
    NORMAL_RISK             : 0,
    
    MONEY_RISK              : 5,
    SMS_RISK                : 5,
    PHONE_RISK              : 5,
    INTERNET_RISK           : 2,
    PRIVACY_RISK            : 5,
    DYNAMIC_RISK            : 5,

    BINARY_RISK             : 10,
    EXPLOIT_RISK            : 15,
}

GENERAL_PERMISSIONS_RISK = {
    "dangerous"                 : DANGEROUS_RISK,
    "signatureOrSystem"         : SIGNATURE_SYSTEM_RISK,
    "signature"                 : SIGNATURE_RISK,
    "normal"                    : NORMAL_RISK,
}

PERMISSIONS_RISK = {
    "SEND_SMS"                  : [ MONEY_RISK, SMS_RISK ],
    
    "RECEIVE_SMS"               : [ SMS_RISK ],
    "READ_SMS"                  : [ SMS_RISK ],
    "WRITE_SMS"                 : [ SMS_RISK ],
    "RECEIVE_SMS"               : [ SMS_RISK ],
    "RECEIVE_MMS"               : [ SMS_RISK ],


    "PHONE_CALL"                : [ MONEY_RISK ],
    "PROCESS_OUTGOING_CALLS"    : [ MONEY_RISK ],
    "CALL_PRIVILEGED"           : [ MONEY_RISK ],


    "INTERNET"                  : [ MONEY_RISK, INTERNET_RISK ],
    
    "READ_PHONE_STATE"          : [ PRIVACY_RISK ],
    "READ_CONTACTS"             : [ PRIVACY_RISK ],
    "READ_HISTORY_BOOKMARKS"    : [ PRIVACY_RISK ],
    "ACCESS_FINE_LOCATION"      : [ PRIVACY_RISK ],
    "ACCESS_COARSE_LOCATION"    : [ PRIVACY_RISK ],
}

LOW_RISK                    = "low"
AVERAGE_RISK                = "average"
HIGH_RISK                   = "high"
UNACCEPTABLE_RISK           = "unacceptable"

NULL_MALWARE_RISK           = "null"
AVERAGE_MALWARE_RISK        = "average"
HIGH_MALWARE_RISK           = "high"
UNACCEPTABLE_MALWARE_RISK   = "unacceptable"

from androguard.core.androconf import error, warning, debug, set_debug, get_debug
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS

def add_system_rule(system, rule_name, rule) :
    system.rules[ rule_name ] = rule

def create_system_risk() :
    try :
        import fuzzy
    except ImportError :
        error("please install pyfuzzy to use this module !")

    import fuzzy.System
    import fuzzy.InputVariable
    import fuzzy.fuzzify.Plain
    import fuzzy.OutputVariable
    import fuzzy.defuzzify.COGS
    import fuzzy.defuzzify.COG
    import fuzzy.defuzzify.MaxRight
    import fuzzy.defuzzify.MaxLeft
    import fuzzy.defuzzify.LM
    import fuzzy.set.Polygon
    import fuzzy.set.Singleton
    import fuzzy.set.Triangle
    import fuzzy.Adjective
    import fuzzy.operator.Input
    import fuzzy.operator.Compound
    import fuzzy.norm.Min
    import fuzzy.norm.Max
    import fuzzy.Rule
    import fuzzy.defuzzify.Dict

    system = fuzzy.System.System()

    input_Dangerous_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Money_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Privacy_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Binary_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Internet_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Dynamic_Risk = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    
    # Input variables

        # Dangerous Risk
    system.variables["input_Dangerous_Risk"] = input_Dangerous_Risk
    input_Dangerous_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (8.0, 1.0), (12.0, 0.0)]) )
    input_Dangerous_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(8.0, 0.0), (50.0, 1.0), (60.0, 0.0)]) )
    input_Dangerous_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(50.0, 0.0), (85.0, 1.0), (95.0, 0.0)]) )
    input_Dangerous_Risk.adjectives[UNACCEPTABLE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(85.0, 0.0), (100.0, 1.0)]) )

        # Money Risk
    system.variables["input_Money_Risk"] = input_Money_Risk
    input_Money_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (3.0, 0.0)]) )
    input_Money_Risk.adjectives[UNACCEPTABLE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0), (5.0, 1.0), (30.0, 1.0)]) )

        # Privacy Risk
    system.variables["input_Privacy_Risk"] = input_Privacy_Risk
    input_Privacy_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (6.0, 1.0), (10.0, 0.0)]) )
    input_Privacy_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(6.0, 0.0), (10.0, 1.0), (20.0, 0.0)]) )
    input_Privacy_Risk.adjectives[UNACCEPTABLE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(15.0, 0.0), (20.0, 1.0), (30.0, 1.0)]) )
    
        # Binary Risk
    system.variables["input_Binary_Risk"] = input_Binary_Risk
    input_Binary_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (6.0, 1.0), (10.0, 0.0)]) )
    input_Binary_Risk.adjectives[AVERAGE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(6.0, 0.0), (10.0, 1.0), (15.0, 0.0)]) )
    input_Binary_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(10.0, 0.0), (20.0, 1.0), (24.0, 0.0)]) )
    input_Binary_Risk.adjectives[UNACCEPTABLE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(23.0, 0.0), (30.0, 1.0), (40.0, 1.0)]) )

        # Internet Risk
    system.variables["input_Internet_Risk"] = input_Internet_Risk
    #input_Internet_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (1.0, 1.0)]) )
    input_Internet_Risk.adjectives[HIGH_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(1.0, 0.0), (5.0, 1.0), (30.0, 1.0)]) )

        # Dynamic Risk
    system.variables["input_Dynamic_Risk"] = input_Dynamic_Risk
    input_Dynamic_Risk.adjectives[LOW_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (3.0, 0.0)]))
    input_Dynamic_Risk.adjectives[UNACCEPTABLE_RISK] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(4.0, 0.0), (5.0, 1.0), (50.0, 1.0)]) )

    # Output variables
    output_malware_risk = fuzzy.OutputVariable.OutputVariable(
                            defuzzify=fuzzy.defuzzify.COGS.COGS(),
                            description="malware risk",
                            min=0.0,max=100.0,
                        )
    
    #output_malware_risk = fuzzy.OutputVariable.OutputVariable(defuzzify=fuzzy.defuzzify.Dict.Dict())

    output_malware_risk.adjectives[NULL_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(0.0))
    output_malware_risk.adjectives[AVERAGE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(30.0))
    output_malware_risk.adjectives[HIGH_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(60.0))
    output_malware_risk.adjectives[UNACCEPTABLE_MALWARE_RISK] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(100.0))
    
    system.variables["output_malware_risk"] = output_malware_risk

    # Rules
    #RULE 0: DYNAMIC 
    add_system_rule(system, "r0", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[LOW_RISK] )
                    )
    )
    
    add_system_rule(system, "r0a", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Dynamic_Risk"].adjectives[UNACCEPTABLE_RISK] )
                    )
    )
    

    #RULE 1: MONEY
    add_system_rule(system, "r1", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[NULL_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[LOW_RISK] )
                    )
    )

    add_system_rule(system, "r1a", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Money_Risk"].adjectives[UNACCEPTABLE_RISK] )
                    )
    )
    
    #RULE 3 : BINARY
    add_system_rule(system, "r3", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[AVERAGE_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Binary_Risk"].adjectives[AVERAGE_RISK] )
                    )
    )
    
    add_system_rule(system, "r3a", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[HIGH_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Binary_Risk"].adjectives[HIGH_RISK] )
                    )
    )

    add_system_rule(system, "r3b", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Binary_Risk"].adjectives[UNACCEPTABLE_RISK] )
                    )
    )
    
    # PRIVACY + INTERNET
    add_system_rule(system, "r5", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[HIGH_MALWARE_RISK]],
                                        operator=fuzzy.operator.Compound.Compound(
                                            fuzzy.norm.Min.Min(),
                                            fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[LOW_RISK] ),
                                            fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ) )
                    )
    )
    add_system_rule(system, "r5a", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_MALWARE_RISK]],
                                        operator=fuzzy.operator.Compound.Compound(
                                            fuzzy.norm.Min.Min(),
                                            fuzzy.operator.Input.Input( system.variables["input_Privacy_Risk"].adjectives[HIGH_RISK] ),
                                            fuzzy.operator.Input.Input( system.variables["input_Internet_Risk"].adjectives[HIGH_RISK] ) )
                    )
    )
    
    add_system_rule(system, "r6", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[HIGH_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Dangerous_Risk"].adjectives[HIGH_RISK] )
                    )
    )
    
    add_system_rule(system, "r6a", fuzzy.Rule.Rule(
                                        adjective=[system.variables["output_malware_risk"].adjectives[UNACCEPTABLE_RISK]],
                                        operator=fuzzy.operator.Input.Input( system.variables["input_Dangerous_Risk"].adjectives[UNACCEPTABLE_RISK] )
                    )
    )


    return system


PERFECT_SCORE               = "perfect"
HIGH_SCORE                  = "high"
AVERAGE_SCORE               = "average"
LOW_SCORE                   = "low"
NULL_METHOD_SCORE           = "null"
AVERAGE_METHOD_SCORE        = "average"
HIGH_METHOD_SCORE           = "high"
PERFECT_METHOD_SCORE        = "perfect"

def create_system_method_score() :
    try :
        import fuzzy
    except ImportError :
        error("please install pyfuzzy to use this module !")

    import fuzzy.System
    import fuzzy.InputVariable
    import fuzzy.fuzzify.Plain
    import fuzzy.OutputVariable
    import fuzzy.defuzzify.COGS
    import fuzzy.set.Polygon
    import fuzzy.set.Singleton
    import fuzzy.set.Triangle
    import fuzzy.Adjective
    import fuzzy.operator.Input
    import fuzzy.operator.Compound
    import fuzzy.norm.Min
    import fuzzy.norm.Max
    import fuzzy.Rule
    
    system = fuzzy.System.System()

    input_Length_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Match_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_AndroidEntropy_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_JavaEntropy_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Permissions_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Similarity_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    
    # Input variables

        # Length 
    system.variables["input_Length_MS"] = input_Length_MS
    input_Length_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (50.0, 1.0), (100.0, 0.0)]) )
    input_Length_MS.adjectives[AVERAGE_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(50.0, 0.0), (100.0, 1.0), (150.0, 1.0), (300.0, 0.0)]) )
    input_Length_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(150.0, 0.0), (200.0, 1.0), (300.0, 1.0), (400.0, 0.0)]) )
    input_Length_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(350.0, 0.0), (400.0, 1.0), (500.0, 1.0)]) )

        # Match
    system.variables["input_Match_MS"] = input_Match_MS
    input_Match_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (20.0, 1.0), (50.0, 0.0)]) )
    input_Match_MS.adjectives[AVERAGE_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(40.0, 0.0), (45.0, 1.0), (60.0, 1.0), (80.0, 0.0)]) )
    input_Match_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(75.0, 0.0), (90.0, 1.0), (98.0, 1.0), (99.0, 0.0)]) )
    input_Match_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(98.0, 0.0), (100.0, 1.0)]) )
    #input_Match_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Singleton.Singleton( 100.0 ) )

        # Android Entropy
    system.variables["input_AndroidEntropy_MS"] = input_AndroidEntropy_MS
    input_AndroidEntropy_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (4.0, 0.0)]) )
    input_AndroidEntropy_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (30.0, 1.0)]) )

        # Java Entropy
    system.variables["input_JavaEntropy_MS"] = input_JavaEntropy_MS
    input_JavaEntropy_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (4.0, 0.0)]) )
    input_JavaEntropy_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (30.0, 1.0)]) )
    
        # Permissions
    system.variables["input_Permissions_MS"] = input_Permissions_MS
    input_Permissions_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (3.0, 1.0), (4.0, 0.0)]) )
    input_Permissions_MS.adjectives[AVERAGE_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (8.0, 1.0), (9.0, 0.0)]) )
    input_Permissions_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(8.0, 0.0), (10.0, 1.0), (12.0, 1.0), (13.0, 0.0)]) )
    input_Permissions_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(12.0, 0.0), (13.0, 1.0), (20.0, 1.0)]) )
    
        # Similarity Match 
    system.variables["input_Similarity_MS"] = input_Similarity_MS
    input_Similarity_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (0.1, 1.0), (0.3, 0.0)]) )
    input_Similarity_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.3, 0.0), (0.35, 1.0), (0.4, 1.0)]) )
    

    # Output variables
    output_method_score = fuzzy.OutputVariable.OutputVariable(
                                defuzzify=fuzzy.defuzzify.COGS.COGS(),
                                description="method score",
                                min=0.0,max=100.0,
                             )
    output_method_score.adjectives[NULL_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(0.0))
    output_method_score.adjectives[AVERAGE_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(50.0))
    output_method_score.adjectives[HIGH_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(80.0))
    output_method_score.adjectives[PERFECT_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(100.0))

    system.variables["output_method_score"] = output_method_score
    
    add_system_rule(system, "android entropy null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_AndroidEntropy_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "java entropy null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_JavaEntropy_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "permissions null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "permissions average", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[AVERAGE_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[AVERAGE_SCORE] ))
    )
    
    add_system_rule(system, "permissions high", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[HIGH_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[HIGH_SCORE] ))
    )
   
    add_system_rule(system, "permissions perfect", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[PERFECT_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[PERFECT_SCORE] ))
    )
   
    add_system_rule(system, "similarity low", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Similarity_MS"].adjectives[LOW_SCORE] ))
    )

    add_system_rule(system, "length match perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[PERFECT_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_Match_MS"].adjectives[PERFECT_SCORE] ) )
                                    )
    )

    add_system_rule(system, "length match null", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[NULL_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[LOW_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_Match_MS"].adjectives[PERFECT_SCORE] ) )
                                    )
    )

    add_system_rule(system, "length AndroidEntropy perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[HIGH_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_AndroidEntropy_MS"].adjectives[HIGH_SCORE] ) )
                                    )
    )
    
    add_system_rule(system, "length JavaEntropy perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[HIGH_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_JavaEntropy_MS"].adjectives[HIGH_SCORE] ) )
                                    )
    )


    add_system_rule(system, "length similarity perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[PERFECT_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_Similarity_MS"].adjectives[HIGH_SCORE] ),
                                        )
                                    )
    )

    add_system_rule(system, "length similarity average", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_score"].adjectives[HIGH_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[AVERAGE_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_Similarity_MS"].adjectives[HIGH_SCORE] ),
                                        )
                                    )
    )

    return system

def create_system_method_one_score() :
    try :
        import fuzzy
    except ImportError :
        error("please install pyfuzzy to use this module !")

    import fuzzy.System
    import fuzzy.InputVariable
    import fuzzy.fuzzify.Plain
    import fuzzy.OutputVariable
    import fuzzy.defuzzify.COGS
    import fuzzy.set.Polygon
    import fuzzy.set.Singleton
    import fuzzy.set.Triangle
    import fuzzy.Adjective
    import fuzzy.operator.Input
    import fuzzy.operator.Compound
    import fuzzy.norm.Min
    import fuzzy.norm.Max
    import fuzzy.Rule
    
    system = fuzzy.System.System()

    input_Length_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_AndroidEntropy_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_JavaEntropy_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    input_Permissions_MS = fuzzy.InputVariable.InputVariable(fuzzify=fuzzy.fuzzify.Plain.Plain())
    
    # Input variables

        # Length 
    system.variables["input_Length_MS"] = input_Length_MS
    input_Length_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (50.0, 1.0), (100.0, 0.0)]) )
    input_Length_MS.adjectives[AVERAGE_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(50.0, 0.0), (100.0, 1.0), (150.0, 1.0), (300.0, 0.0)]) )
    input_Length_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(150.0, 0.0), (200.0, 1.0), (300.0, 1.0), (400.0, 0.0)]) )
    input_Length_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(350.0, 0.0), (400.0, 1.0), (500.0, 1.0)]) )

        # Android Entropy
    system.variables["input_AndroidEntropy_MS"] = input_AndroidEntropy_MS
    input_AndroidEntropy_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (4.0, 0.0)]) )
    input_AndroidEntropy_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (30.0, 1.0)]) )

        # Java Entropy
    system.variables["input_JavaEntropy_MS"] = input_JavaEntropy_MS
    input_JavaEntropy_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (2.0, 1.0), (4.0, 0.0)]) )
    input_JavaEntropy_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (30.0, 1.0)]) )
    
        # Permissions
    system.variables["input_Permissions_MS"] = input_Permissions_MS
    input_Permissions_MS.adjectives[LOW_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(0.0, 1.0), (3.0, 1.0), (4.0, 0.0)]) )
    input_Permissions_MS.adjectives[AVERAGE_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(3.0, 0.0), (4.0, 1.0), (8.0, 1.0), (9.0, 0.0)]) )
    input_Permissions_MS.adjectives[HIGH_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(8.0, 0.0), (10.0, 1.0), (12.0, 1.0), (13.0, 0.0)]) )
    input_Permissions_MS.adjectives[PERFECT_SCORE] = fuzzy.Adjective.Adjective( fuzzy.set.Polygon.Polygon([(12.0, 0.0), (13.0, 1.0), (20.0, 1.0)]) )
    
    # Output variables
    output_method_score = fuzzy.OutputVariable.OutputVariable(
                                defuzzify=fuzzy.defuzzify.COGS.COGS(),
                                description="method one score",
                                min=0.0,max=100.0,
                             )
    output_method_score.adjectives[NULL_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(0.0))
    output_method_score.adjectives[AVERAGE_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(50.0))
    output_method_score.adjectives[HIGH_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(80.0))
    output_method_score.adjectives[PERFECT_METHOD_SCORE] = fuzzy.Adjective.Adjective(fuzzy.set.Singleton.Singleton(100.0))

    system.variables["output_method_one_score"] = output_method_score
    
    add_system_rule(system, "android entropy null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_AndroidEntropy_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "java entropy null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_JavaEntropy_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "permissions null", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[NULL_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[LOW_SCORE] ))
    )
    
    add_system_rule(system, "permissions average", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[AVERAGE_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[AVERAGE_SCORE] ))
    )
    
    add_system_rule(system, "permissions high", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[HIGH_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[HIGH_SCORE] ))
    )
   
    add_system_rule(system, "permissions perfect", fuzzy.Rule.Rule(
                                                        adjective=[system.variables["output_method_one_score"].adjectives[PERFECT_METHOD_SCORE]],
                                                        operator=fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[PERFECT_SCORE] ))
    )
   

    add_system_rule(system, "length permissions perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_one_score"].adjectives[PERFECT_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_Permissions_MS"].adjectives[PERFECT_SCORE] ) )
                                    )
    )

    add_system_rule(system, "length AndroidEntropy perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_one_score"].adjectives[HIGH_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_AndroidEntropy_MS"].adjectives[HIGH_SCORE] ) )
                                    )
    )
    
    add_system_rule(system, "length JavaEntropy perfect", fuzzy.Rule.Rule(
                                    adjective=[system.variables["output_method_one_score"].adjectives[HIGH_METHOD_SCORE]],
                                    operator=fuzzy.operator.Compound.Compound(
                                        fuzzy.norm.Min.Min(),
                                        fuzzy.operator.Input.Input( system.variables["input_Length_MS"].adjectives[PERFECT_SCORE] ),
                                        fuzzy.operator.Input.Input( system.variables["input_JavaEntropy_MS"].adjectives[HIGH_SCORE] ) )
                                    )
    )

    return system

def export_system(system, directory) :
    from fuzzy.doc.plot.gnuplot import doc
    
    d = doc.Doc(directory)
    d.createDoc(system)

    import fuzzy.doc.structure.dot.dot
    import subprocess
    for name,rule in system.rules.items():
            cmd = "dot -T png -o '%s/fuzzy-Rule %s.png'" % (directory,name)
            f = subprocess.Popen(cmd, shell=True, bufsize=32768, stdin=subprocess.PIPE).stdin
            fuzzy.doc.structure.dot.dot.print_header(f,"XXX")
            fuzzy.doc.structure.dot.dot.print_dot(rule,f,system,"")
            fuzzy.doc.structure.dot.dot.print_footer(f)
    cmd = "dot -T png -o '%s/fuzzy-System.png'" % directory
    f = subprocess.Popen(cmd, shell=True, bufsize=32768, stdin=subprocess.PIPE).stdin
    fuzzy.doc.structure.dot.dot.printDot(system,f)

    d.overscan=0
    in_vars = [name for name,var in system.variables.items() if isinstance(var,fuzzy.InputVariable.InputVariable)]
    out_vars = [name for name,var in system.variables.items() if isinstance(var,fuzzy.OutputVariable.OutputVariable)]
    
    if len(in_vars) == 2 and not (
            isinstance(system.variables[in_vars[0]].fuzzify,fuzzy.fuzzify.Dict.Dict)
        or
            isinstance(system.variables[in_vars[1]].fuzzify,fuzzy.fuzzify.Dict.Dict)
    ):
        for out_var in out_vars:
            args = []
            if isinstance(system.variables[out_var].defuzzify,fuzzy.defuzzify.Dict.Dict):
                for adj in system.variables[out_var].adjectives:
                    d.create3DPlot_adjective(system, in_vars[0], in_vars[1], out_var, adj, {})
            else:
                d.create3DPlot(system, in_vars[0], in_vars[1], out_var, {})

SYSTEM = None
class RiskIndicator :
    """
    Calculate the risk to install a specific android application by using :
        Permissions : 
            - dangerous
            - signatureOrSystem
            - signature
            - normal
        
            - money
            - internet
            - sms
            - call
            - privacy

         API :
            - DexClassLoader

         Files :
            - binary file
            - shared library

        note : pyfuzzy without fcl support (don't install antlr)
    """
    def __init__(self) :
        #set_debug()
        global SYSTEM

        if SYSTEM == None :
            SYSTEM = create_system_risk()
#            export_system( SYSTEM, "./output" )
        
        self.system_method_risk = create_system_method_one_score()

    def __eval_risk_perm(self, list_details_permissions, risks) :
        for i in list_details_permissions :
            permission = i
            if permission.find(".") != -1 :
                permission = permission.split(".")[-1]
#            print permission, GENERAL_PERMISSIONS_RISK[ list_details_permissions[ i ][0] ]
          
            risk_type = GENERAL_PERMISSIONS_RISK[ list_details_permissions[ i ][0] ]

            risks[ DANGEROUS_RISK ] += RISK_VALUES [ risk_type ]

            try :
                for j in PERMISSIONS_RISK[ permission ] :
                    risks[ j ] += RISK_VALUES[ j ]
            except KeyError :
                pass

    def __eval_risk_dyn(self, vmx, risks) :
        for m, _ in vmx.tainted_packages.get_packages() :
            if m.get_info() == "Ldalvik/system/DexClassLoader;" :
                for path in m.get_paths() :
                    if path.get_access_flag() == analysis.TAINTED_PACKAGE_CREATE :
                        risks[ DYNAMIC_RISK ] = RISK_VALUES[ DYNAMIC_RISK ]
                        return

    def __eval_risk_bin(self, list_details_files, risks) :
        for i in list_details_files :
            if "ELF" in list_details_files[ i ] :
                # shared library
                if "shared" in list_details_files[ i ] :
                    risks[ BINARY_RISK ] += RISK_VALUES [ BINARY_RISK ]
                # binary 
                else :
                    risks[ BINARY_RISK ] += RISK_VALUES [ EXPLOIT_RISK ]

    def __eval_risks(self, risks) :
        output_values = {"output_malware_risk" : 0.0}
        input_val = {}
        input_val['input_Dangerous_Risk'] = risks[ DANGEROUS_RISK ]
        input_val['input_Money_Risk'] = risks[ MONEY_RISK ]
        input_val['input_Privacy_Risk'] = risks[ PRIVACY_RISK ]
        input_val['input_Binary_Risk'] = risks[ BINARY_RISK ]
        input_val['input_Internet_Risk'] = risks[ INTERNET_RISK ]
        input_val['input_Dynamic_Risk'] = risks[ DYNAMIC_RISK ]

        #print input_val,
        
        SYSTEM.calculate(input=input_val, output = output_values)

        val = output_values[ "output_malware_risk" ]
        return val

    def with_apk(self, apk_file, analysis=None, analysis_method=None) :
        """
            @param apk_file : an L{APK} object

            @rtype : return the risk of the apk file (from 0.0 to 100.0)
        """

        if apk_file.is_valid_APK() :
            if analysis == None :
                return self.with_apk_direct( apk_file )
            else :
                return self.with_apk_analysis( apk_file, analysis_method )
        return -1
    
    def with_apk_direct(self, apk) :
        risks = { DANGEROUS_RISK    : 0.0,
                  MONEY_RISK        : 0.0,
                  PRIVACY_RISK      : 0.0,
                  INTERNET_RISK     : 0.0,
                  BINARY_RISK       : 0.0,
                  DYNAMIC_RISK      : 0.0,
                }

        self.__eval_risk_perm( apk.get_details_permissions(), risks )
        self.__eval_risk_bin( apk.get_files_types(), risks )
        
        val = self.__eval_risks( risks )

        return val

    def with_apk_analysis( self, apk, analysis_method=None ) :
        return self.with_dex( apk.get_dex(), apk, analysis_method )

    def with_dex(self, dex_file, apk=None, analysis_method=None) :
        """
            @param dex_file : a buffer

            @rtype : return the risk of the dex file (from 0.0 to 100.0)
        """
        try : 
            vm = dvm.DalvikVMFormat( dex_file )
        except Exception, e :
            return -1

        vmx = analysis.VMAnalysis( vm )


        return self.with_dex_direct( vm, vmx, apk, analysis_method )

    def with_dex_direct(self, vm, vmx, apk=None, analysis_method=None) :
        risks = { DANGEROUS_RISK    : 0.0,
                  MONEY_RISK        : 0.0,
                  PRIVACY_RISK      : 0.0,
                  INTERNET_RISK     : 0.0,
                  BINARY_RISK       : 0.0,
                  DYNAMIC_RISK      : 0.0,
                }
        
        if apk :
            self.__eval_risk_bin( apk.get_files_types(), risks )
            self.__eval_risk_perm( apk.get_details_permissions(), risks )
        else :
            d = {}
            for i in vmx.get_permissions( [] ) :
                d[ i ] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][i] 
            self.__eval_risk_perm( d, risks )

        self.__eval_risk_dyn( vmx, risks )
        
        val = self.__eval_risks( risks )
        
        if analysis_method == None :
            return val, {}


        ##########################
        score_order_sign = {}


        import sys
        sys.path.append("./elsim")
        from elsim.elsign.libelsign import libelsign
        for method in vm.get_methods() :
            if method.get_length() < 80 :
                continue

            score_order_sign[ method ] = self.get_method_score( method.get_length(),
                                 libelsign.entropy( vmx.get_method_signature(method, "L4", { "L4" : { "arguments" : ["Landroid"] } } ).get_string() ),
                                 libelsign.entropy( vmx.get_method_signature(method, "L4", { "L4" : { "arguments" : ["Ljava"] } } ).get_string() ),
                                 map(lambda perm : (perm, DVM_PERMISSIONS["MANIFEST_PERMISSION"][ perm ]), vmx.get_permissions_method( method )),
            )

            
        for v in sorted(score_order_sign, key=lambda x : score_order_sign[x], reverse=True) :
            print v.get_name(), v.get_class_name(), v.get_descriptor(), v.get_length(), score_order_sign[ v ]

        ##########################

        return val, score_order_sign
       
   
    def get_method_score(self, length, android_entropy, java_entropy, permissions) :
        val_permissions = 0
        for i in permissions :
            val_permissions += RISK_VALUES[ GENERAL_PERMISSIONS_RISK[ i[1][0] ] ]

            try :
                for j in PERMISSIONS_RISK[ i[0] ] :
                    val_permissions += RISK_VALUES[ j ]
            except KeyError :
                pass
        
        print length, android_entropy, java_entropy, val_permissions

        output_values = {"output_method_one_score" : 0.0}
        input_val = {}
        input_val['input_Length_MS'] = length
        input_val['input_AndroidEntropy_MS'] = android_entropy
        input_val['input_JavaEntropy_MS'] = java_entropy
        input_val['input_Permissions_MS'] = val_permissions
       
        self.system_method_risk.calculate(input=input_val, output = output_values)
        score = output_values[ "output_method_one_score" ]

        return score

    def simulate(self, risks) :
        return self.__eval_risks( risks )


class MethodScore :
    def __init__(self, length, matches, android_entropy, java_entropy, permissions, similarity_matches) :
        self.system = create_system_method_score()
        #export_system( self.system, "./output" )

        
        val_permissions = 0
        for i in permissions :
            val_permissions += RISK_VALUES[ GENERAL_PERMISSIONS_RISK[ i[1][0] ] ]

            try :
                for j in PERMISSIONS_RISK[ i[0] ] :
                    val_permissions += RISK_VALUES[ j ]
            except KeyError :
                pass
        
        print length, matches, android_entropy, java_entropy, similarity_matches, val_permissions

        output_values = {"output_method_score" : 0.0}
        input_val = {}
        input_val['input_Length_MS'] = length
        input_val['input_Match_MS'] = matches
        input_val['input_AndroidEntropy_MS'] = android_entropy
        input_val['input_JavaEntropy_MS'] = java_entropy
        input_val['input_Permissions_MS'] = val_permissions
        input_val['input_Similarity_MS'] = similarity_matches
       
        self.system.calculate(input=input_val, output = output_values)
        self.score = output_values[ "output_method_score" ]

    def get_score(self) :
        return self.score
