/**
***************************************************************************************************
* @vd_noapi
* @file SfEnum.h
* @brief Security framework [SF]
* @author Yurii Kryvokhata (y.kryvokhata@samsung.com)
* @date Created Mar 25, 2014 10:44
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12 
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
***************************************************************************************************
*/

#ifndef _SF_ENUM_H_
#define _SF_ENUM_H_

#include "SfConfig.h"
#include "SfTypes.h"

/**
@warning Keep attention when __FLAG__ is zeroed
*/
#define IS_FLAG_SET(__ENUM_VALUE__, __FLAG__) ((__ENUM_VALUE__ & __FLAG__) == __FLAG__ )

#ifdef __cplusplus 

#define SF_BEGIN_ENUM(__NAME__) class __NAME__  {          \
public:                                                     \
    enum __NAME__##Type{

#define SF_END_ENUM(__NAME__, __DEFAULT__) };              \
    __NAME__(const __NAME__##Type& value = __DEFAULT__) :   \
    m_value(value)                                          \
    {                                                       \
    }                                                       \
    inline Bool IsEqual(const __NAME__##Type& value) const  \
    {                                                       \
        return (m_value == value);                          \
    }                                                       \
    operator __NAME__##Type() const                         \
    {                                                       \
        return m_value;                                     \
    }                                                       \
protected:                                                  \
    __NAME__##Type m_value;                                 \
};


#define SF_BEGIN_FLAGS(__NAME__) class __NAME__  {          \
public:                                                     \
    enum __NAME__##Type{

#define SF_END_FLAGS(__NAME__, __DEFAULT__) };              \
    __NAME__(const __NAME__##Type& value = __DEFAULT__) :   \
    m_value(value)                                          \
    {                                                       \
    }                                                       \
    inline Bool IsFlagSet(const __NAME__##Type& flag) const \
    {                                                       \
        return  IS_FLAG_SET(m_value , flag);                \
    }                                                       \
    inline Bool IsEqual(const __NAME__##Type& value) const  \
    {                                                       \
        return (m_value == value);                          \
    }                                                       \
    operator __NAME__##Type() const                         \
    {                                                       \
        return m_value;                                     \
    }                                                       \
protected:                                                  \
    __NAME__##Type m_value;                                 \
};

#else

#define SF_BEGIN_FLAGS(__NAME__) \
    typedef enum {

#define SF_END_FLAGS(__NAME__, __DEFAULT__) } __NAME__##Type; static const __NAME__##TypeDefault = __DEFAULT__;
#endif

#endif /* !_SF_ENUM_H_ */
