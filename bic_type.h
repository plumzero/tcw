
#ifndef __Basic_Instruction_Command_TYPE_H__
#define __Basic_Instruction_Command_TYPE_H__

/** type of message */
typedef enum _bic_type {
    BIC_TYPE_NONE,
    BIC_TYPE_GUARDRAGON,
    
    BIC_TYPE_P2S_SUMMON,
    BIC_TYPE_P2S_MONSTER,
    BIC_TYPE_P2S_BITRON,
    BIC_TYPE_P2S_BLOCKRON,
    BIC_TYPE_P2S_ARCHIVERON,
    BIC_TYPE_P2S_BOMBER,
    
    BIC_TYPE_S2P_SUMMON,
    BIC_TYPE_S2P_MONSTER,
    BIC_TYPE_S2P_BITRON,
    BIC_TYPE_S2P_BLOCKRON,
    BIC_TYPE_S2P_ARCHIVERON,
    BIC_TYPE_S2P_BOMBER,

    BIC_TYPE_P2C_BETWEEN,
    BIC_TYPE_C2C_BETWEEN,
    
    BIC_TYPE_A2A_START,
    BIC_TYPE_A2B_BETWEEN,
    BIC_TYPE_B2C_BETWEEN,

} BICTYPE;

#endif // ! __Basic_Instruction_Command_TYPE_H__