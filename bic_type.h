
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
    
} BICTYPE;

#endif // ! __Basic_Instruction_Command_TYPE_H__