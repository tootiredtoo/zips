# for i18n
IF(NOT DEFINED LOCALEDIR)
SET(LOCALEDIR "${TZ_SYS_RO_APP}/org.tizen.smart_security/shared/locale")
ENDIF(NOT DEFINED LOCALEDIR)

FILE(GLOB_RECURSE POFILES "*.po")

SET(MSGFMT "${TZ_SYS_BIN}/msgfmt")

FOREACH(pofile ${POFILES})
    MESSAGE("PO: ${pofile}")
    GET_FILENAME_COMPONENT(absPofile ${pofile} ABSOLUTE)
    GET_FILENAME_COMPONENT(lang ${absPofile} NAME_WE)
    SET(moFile ${CMAKE_CURRENT_BINARY_DIR}/${lang}.mo)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${moFile}
        COMMAND ${MSGFMT} -o ${moFile} ${absPofile}
        DEPENDS ${absPofile}
    )
    INSTALL(FILES ${moFile}	DESTINATION ${LOCALEDIR}/${lang}/LC_MESSAGES RENAME smart_security.mo)
    SET(moFiles ${moFiles} ${moFile})
ENDFOREACH(pofile)

MESSAGE(".mo files: ${moFiles}")
ADD_CUSTOM_TARGET(po ALL DEPENDS ${moFiles})
