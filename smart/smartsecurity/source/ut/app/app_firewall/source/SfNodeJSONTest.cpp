/**
****************************************************************************************************
* @file SfNodeJSONTest.cpp
* @brief Security framework [SF] implementation: unit test for class json/SfNode.h
* @author Anton Skakun (a.skakun@samsung.com)
* @date Created Jul 2, 2014 09:47
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/
// local
#include "SfNodeJSONTest.h"

// project
#include "libcore/SfMemory.h"

/**
****************************************************************************************************
* @brief Adds the specified fixture suite to the unnamed registry
****************************************************************************************************
*/
CPPUNIT_TEST_SUITE_REGISTRATION( SfNodeJSONTest );

/**
****************************************************************************************************
* @brief attributes
****************************************************************************************************
*/
static const std::string c_stringAttr       = "stringAttr";
static const std::string c_Uint8Attr        = "Uint8Attr";
static const std::string c_Uint16Attr       = "Uint16Attr";
static const std::string c_Uint32Attr       = "Uint32Attr";
static const std::string c_Uint64Attr       = "Uint64Attr";
static const std::string c_Int8Attr         = "Int8Attr";
static const std::string c_Int16Attr        = "Int16Attr";
static const std::string c_Int32Attr        = "Int32Attr";
static const std::string c_Int64Attr        = "Int64Attr";
static const std::string c_boolAttrTrue     = "boolAttrTrue";
static const std::string c_boolAttrFalse    = "boolAttrFalse";
static const std::string c_nullAttr         = "nullAttr";

/**
****************************************************************************************************
* @brief values
****************************************************************************************************
*/
static const std::string c_stringValue      = "stringValue";
static const std::string c_nullValue        = "null";
static const Uint8       c_Uint8Value       = Uint8(2);
static const Uint16      c_Uint16Value      = Uint16(3);
static const Uint32      c_Uint32Value      = Uint32(4);
static const Uint64      c_Uint64Value      = Uint32(5);
static const Int8        c_Int8Value        = Int8(-6);
static const Int16       c_Int16Value       = Int16(-7);
static const Int32       c_Int32Value       = Int32(-8);
static const Int64       c_Int64Value       = Int64(-9);
static const bool        c_boolTrueValue    = true;
static const bool        c_boolFalseValue   = false;

/**
****************************************************************************************************
* @brief examples from http://json.org/example
****************************************************************************************************
*/
static const std::string c_example1 = "{\"glossary\":{\"title\":\"exampleglossary\",\"GlossDiv\":"\
"{\"title\":\"S\",\"GlossList\":{\"GlossEntry\":{\"ID\":\"SGML\",\"SortAs\":\"SGML\",\"GlossTerm\""\
":\"StandardGeneralizedMarkupLanguage\",\"Acronym\":\"SGML\",\"Abbrev\":\"ISO8879:1986\","\
"\"GlossDef\":{\"para\":\"Ameta-markuplanguage,usedtocreatemarkuplanguagessuchasDocBook.\","\
"\"GlossSeeAlso\":[\"GML\",\"XML\"]},\"GlossSee\":\"markup\"}}}}}";

static const std::string c_example2 = "{\"menu\":{\"id\":\"file\",\"value\":\"File\",\"popup\":"\
"{\"menuitem\":[{\"value\":\"New\",\"onclick\":\"CreateNewDoc()\"},{\"value\":\"Open\","\
"\"onclick\":\"OpenDoc()\"},{\"value\":\"Close\",\"onclick\":\"CloseDoc()\"}]}}}";

static const std::string c_example3 = "{\"widget\":{\"debug\":\"on\",\"window\":{\"title\":"\
"\"SampleKonfabulatorWidget\",\"name\":\"main_window\",\"width\":500,\"height\":500},\"image\""\
":{\"src\":\"Images/Sun.png\",\"name\":\"sun1\",\"hOffset\":250,\"vOffset\":250,\"alignment\""\
":\"center\"},\"text\":{\"data\":\"ClickHere\",\"size\":36,\"style\":\"bold\",\"name\":\"text1\","\
"\"hOffset\":250,\"vOffset\":100,\"alignment\":\"center\",\"onMouseUp\":"\
"\"sun1.opacity=(sun1.opacity/100)*90;\"}}}";

static const std::string c_example4 = "{\"web-app\":{\"servlet\":[{\"servlet-name\":\"cofaxCDS\","\
"\"servlet-class\":\"org.cofax.cds.CDSServlet\",\"init-param\":{\"configGlossary:installationAt\""\
":\"Philadelphia, PA\",\"configGlossary:adminEmail\":\"ksm@pobox.com\","\
"\"configGlossary:poweredBy\":\"Cofax\",\"configGlossary:poweredByIcon\":\"/images/cofax.gif\","\
"\"configGlossary:staticPath\":\"/content/static\",\"templateProcessorClass\":"\
"\"org.cofax.WysiwygTemplate\",\"templateLoaderClass\":\"org.cofax.FilesTemplateLoader\","\
"\"templatePath\":\"templates\",\"templateOverridePath\":\"\",\"defaultListTemplate\":"\
"\"listTemplate.htm\",\"defaultFileTemplate\":\"articleTemplate.htm\",\"useJSP\":false,"\
"\"jspListTemplate\":\"listTemplate.jsp\",\"jspFileTemplate\":\"articleTemplate.jsp\","\
"\"cachePackageTagsTrack\":200,\"cachePackageTagsStore\":200,\"cachePackageTagsRefresh\":60,"\
"\"cacheTemplatesTrack\":100,\"cacheTemplatesStore\":50,\"cacheTemplatesRefresh\":15,"\
"\"cachePagesTrack\":200,\"cachePagesStore\":100,\"cachePagesRefresh\":10,\"cachePagesDirtyRead\""\
":10,\"searchEngineListTemplate\":\"forSearchEnginesList.htm\",\"searchEngineFileTemplate\":"\
"\"forSearchEngines.htm\",\"searchEngineRobotsDb\":\"WEB-INF/robots.db\",\"useDataStore\":true,"\
"\"dataStoreClass\":\"org.cofax.SqlDataStore\",\"redirectionClass\":\"org.cofax.SqlRedirection\","\
"\"dataStoreName\":\"cofax\",\"dataStoreDriver\":\"com.microsoft.jdbc.sqlserver.SQLServerDriver\","\
"\"dataStoreUrl\":\"jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon\","\
"\"dataStoreUser\":\"sa\",\"dataStorePassword\":\"dataStoreTestQuery\",\"dataStoreTestQuery\":"\
"\"SET NOCOUNT ON;select test='test';\",\"dataStoreLogFile\":"\
"\"/usr/local/tomcat/logs/datastore.log\",\"dataStoreInitConns\":10,\"dataStoreMaxConns\":100,"\
"\"dataStoreConnUsageLimit\":100,\"dataStoreLogLevel\":\"debug\",\"maxUrlLength\":500}},"\
"{\"servlet-name\":\"cofaxEmail\",\"servlet-class\":\"org.cofax.cds.EmailServlet\",\"init-param\""\
":{\"mailHost\":\"mail1\",\"mailHostOverride\":\"mail2\"}},{\"servlet-name\":\"cofaxAdmin\","\
"\"servlet-class\":\"org.cofax.cds.AdminServlet\"},{\"servlet-name\":\"fileServlet\","\
"\"servlet-class\":\"org.cofax.cds.FileServlet\"},{\"servlet-name\":\"cofaxTools\","\
"\"servlet-class\":\"org.cofax.cms.CofaxToolsServlet\",\"init-param\":{\"templatePath\":"\
"\"toolstemplates/\",\"log\":1,\"logLocation\":\"/usr/local/tomcat/logs/CofaxTools.log\","\
"\"logMaxSize\":\"\",\"dataLog\":1,\"dataLogLocation\":\"/usr/local/tomcat/logs/dataLog.log\","\
"\"dataLogMaxSize\":\"\",\"removePageCache\":\"/content/admin/remove?cache=pages&id=\","\
"\"removeTemplateCache\":\"/content/admin/remove?cache=templates&id=\",\"fileTransferFolder\":"\
"\"/usr/local/tomcat/webapps/content/fileTransferFolder\",\"lookInContext\":1,\"adminGroupID\":4,"\
"\"betaServer\":true}}],\"servlet-mapping\":{\"cofaxCDS\":\"/\",\"cofaxEmail\":"\
"\"/cofaxutil/aemail/*\",\"cofaxAdmin\":\"/admin/*\",\"fileServlet\":\"/static/*\",\"cofaxTools\":"\
"\"/tools/*\"},\"taglib\":{\"taglib-uri\":\"cofax.tld\",\"taglib-location\":"\
"\"/WEB-INF/tlds/cofax.tld\"}}}";

static const std::string c_example5 = "{\"menu\":{\"header\":\"SVG Viewer\",\"items\":[{\"id\":"\
"\"Open\"},{\"id\":\"OpenNew\",\"label\":\"Open New\"},null,{\"id\":\"ZoomIn\",\"label\":"\
"\"Zoom In\"},{\"id\":\"ZoomOut\",\"label\":\"Zoom Out\"},{\"id\":\"OriginalView\",\"label\":"\
"\"Original View\"},null,{\"id\":\"Quality\"},{\"id\":\"Pause\"},{\"id\":\"Mute\"},null,{\"id\":"\
"\"Find\",\"label\":\"Find...\"},{\"id\":\"FindAgain\",\"label\":\"Find Again\"},{\"id\":\"Copy\""\
"},{\"id\":\"CopyAgain\",\"label\":\"Copy Again\"},{\"id\":\"CopySVG\",\"label\":\"Copy SVG\"},"\
"{\"id\":\"ViewSVG\",\"label\":\"View SVG\"},{\"id\":\"ViewSource\",\"label\":\"View Source\"},"\
"{\"id\":\"SaveAs\",\"label\":\"Save As\"},null,{\"id\":\"Help\"},{\"id\":\"About\",\"label\":"\
"\"About Adobe CVG Viewer...\"}]}}";

static const std::string c_exampleWithSpaces = "{    \"glossary\": {        \"title\": \"example"\
" glossary\",        \"GlossDiv\": {            \"title\": \"S\",            \"GlossList\": {"\
"                \"GlossEntry\": {                    \"ID\": \"SGML\",                    "\
"\"SortAs\": \"SGML\",                    \"GlossTerm\": \"Standard Generalized Markup Language\","\
"\"Acronym\": \"SGML\",                    \"Abbrev\": \"ISO 8879:1986\",                    "\
"\"GlossDef\": {                        \"para\": \"A meta-markup language, used to create markup"\
" languages such as DocBook.\",                        \"GlossSeeAlso\": [\"GML\", \"XML\"]"\
"                    },                    \"GlossSee\": \"markup\"                }            "\
"}        }    }}";

static const std::string c_exampleWithoutSpaces = "{\"glossary\":{\"title\":\"example glossary\""\
",\"GlossDiv\":{\"title\":\"S\",\"GlossList\":{\"GlossEntry\":{\"ID\":\"SGML\",\"SortAs\":\"SGML\""\
",\"GlossTerm\":\"Standard Generalized Markup Language\",\"Acronym\":\"SGML\",\"Abbrev\":"\
"\"ISO 8879:1986\",\"GlossDef\":{\"para\":\"A meta-markup language, used to create markup "\
"languages such as DocBook.\",\"GlossSeeAlso\":[\"GML\",\"XML\"]},\"GlossSee\":\"markup\"}}}}}";

static const std::string c_manualBuildObjectStep1 = "{\"stringAttr\":\"stringValue\",\"Uint8Attr\""\
":2,\"Uint16Attr\":3,\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,"\
"\"Int32Attr\":-8,\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null}";

static const std::string c_manualBuildObjectStep2 = "{\"stringAttr\":\"stringValue\",\"Uint8Attr\""\
":2,\"Uint16Attr\":3,\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,"\
"\"Int32Attr\":-8,\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null,\"object\":"\
"{\"stringAttr\":\"stringValue\",\"Uint8Attr\":2,\"Uint16Attr\":3,\"Uint32Attr\":4,"\
"\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,\"Int32Attr\":-8,\"Int64Attr\":-9,"\
"\"boolAttrTrue\":true,\"nullAttr\":null}}";

static const std::string c_manualBuildObjectStep3 = "{\"stringAttr\":\"stringValue\",\"Uint8Attr\""\
":2,\"Uint16Attr\":3,\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,"\
"\"Int32Attr\":-8,\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null,\"object\":"\
"{\"stringAttr\":\"stringValue\",\"Uint8Attr\":2,\"Uint16Attr\":3,\"Uint32Attr\":4,"\
"\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,\"Int32Attr\":-8,\"Int64Attr\":-9,"\
"\"boolAttrTrue\":true,\"nullAttr\":null},\"array\":[2,3,4,5,-6,-7,-8,-9,false,"\
"\"stringValue\",null]}";

static const std::string c_manualBuildObjectStep4 = "{\"stringAttr\":\"stringValue\",\"Uint8Attr\""\
":2,\"Uint16Attr\":3,\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,"\
"\"Int32Attr\":-8,\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null,\"object\":"\
"{\"stringAttr\":\"stringValue\",\"Uint8Attr\":2,\"Uint16Attr\":3,\"Uint32Attr\":4,"\
"\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,\"Int32Attr\":-8,\"Int64Attr\":-9,"\
"\"boolAttrTrue\":true,\"nullAttr\":null},\"array\":[2,3,4,5,-6,-7,-8,-9,false,\"stringValue\","\
"null],\"array1\":[{\"stringAttr\":\"stringValue\",\"Uint8Attr\":2,\"Uint16Attr\":3,"\
"\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,\"Int16Attr\":-7,\"Int32Attr\":-8,"\
"\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null},{\"stringAttr\":\"stringValue\","\
"\"Uint8Attr\":2,\"Uint16Attr\":3,\"Uint32Attr\":4,\"Uint64Attr\":5,\"Int8Attr\":-6,"\
"\"Int16Attr\":-7,\"Int32Attr\":-8,\"Int64Attr\":-9,\"boolAttrTrue\":true,\"nullAttr\":null}]}";

/**
****************************************************************************************************
* @brief SfNodeJSONTest implementation
****************************************************************************************************
*/
SfNodeJSONTest::SfNodeJSONTest()
    : TestFixture()
{
}

/**
****************************************************************************************************
*
****************************************************************************************************
*/
SfNodeJSONTest::~SfNodeJSONTest()
{
}

/**
****************************************************************************************************
//@sut      TestParseToString
//@brief    Json parsor json to string
****************************************************************************************************
*/
void SfNodeJSONTest::TestParseToString()
{
    SfJSONNode rootNode;
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_example1 ) ) , 0 );
    CPPUNIT_ASSERT( c_example1 == rootNode.ToString() );

    rootNode.Clear();
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_example2 ) ) , 0 );
    CPPUNIT_ASSERT( c_example2 == rootNode.ToString() );

    rootNode.Clear();
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_example3 ) ) , 0 );
    CPPUNIT_ASSERT( c_example3 == rootNode.ToString() );

    rootNode.Clear();
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_example4 ) ) , 0 );
    CPPUNIT_ASSERT( c_example4 == rootNode.ToString() );

    rootNode.Clear();
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_example5 ) ) , 0 );
    CPPUNIT_ASSERT( c_example5 == rootNode.ToString() );

    rootNode.Clear();
    EXPECT_EQ( SF_SUCCESS( rootNode.Parse( c_exampleWithSpaces ) ) , 0 );
    CPPUNIT_ASSERT( c_exampleWithoutSpaces == rootNode.ToString() );
}

/**
****************************************************************************************************
//@sut      TestManualBuildNodeToString
//@brief    Add Json Node to string
****************************************************************************************************
*/
void SfNodeJSONTest::TestManualBuildNodeToString()
{
    SfJSONNode rootNode;
    BuildDefaultNode( rootNode );
    CPPUNIT_ASSERT( c_manualBuildObjectStep1 == rootNode.ToString() );

    SfJSONNode* pNode = SF_NEW SfJSONNode( "object" );
    BuildDefaultNode( *pNode );
    EXPECT_EQ( SF_SUCCESS( rootNode.PutNode( pNode ) ) , 0 );
    CPPUNIT_ASSERT( c_manualBuildObjectStep2 == rootNode.ToString() );

    SfJSONArrayNode* pArrayNode = SF_NEW SfJSONArrayNode( "array" );
    BuildDefaultSimpleArrayNode( *pArrayNode );
    EXPECT_EQ( SF_SUCCESS( rootNode.PutNode( pArrayNode ) ) , 0 );
    CPPUNIT_ASSERT( c_manualBuildObjectStep3 == rootNode.ToString() );

    SfJSONNode* pNode1 = SF_NEW SfJSONNode;
    SfJSONNode* pNode2 = SF_NEW SfJSONNode;
    SfJSONArrayNode* pArrayNode1 = SF_NEW SfJSONArrayNode( "array1" );
    BuildDefaultNode( *pNode1 );
    BuildDefaultNode( *pNode2 );
    EXPECT_EQ( SF_SUCCESS( pArrayNode1->PutNode( pNode1 ) ) , 0 );
    EXPECT_EQ( SF_SUCCESS( pArrayNode1->PutNode( pNode2 ) ) , 0 );
    EXPECT_EQ( SF_SUCCESS( rootNode.PutNode( pArrayNode1 ) ) , 0 );
    CPPUNIT_ASSERT( c_manualBuildObjectStep4 == rootNode.ToString() );
}

/**
****************************************************************************************************
//@sut      TestPutGetNode
//@brief    Fill Default File Rule Set
****************************************************************************************************
*/
void SfNodeJSONTest::TestPutGetNode()
{
    SfJSONNode rootNode;
    const std::string nodeName      = "node1";
    const std::string arrayNodeName = "arrayNode1";
    SfJSONNode* pNode1              = SF_NEW SfJSONNode( nodeName );
    SfJSONArrayNode* pArrayNode1    = SF_NEW SfJSONArrayNode( arrayNodeName );
    BuildDefaultNode( *pNode1 );
    BuildDefaultSimpleArrayNode( *pArrayNode1 );

    EXPECT_EQ( SF_SUCCESS( rootNode.PutNode( pNode1 ) ), 0 );
    CPPUNIT_ASSERT( rootNode.Size() == 1 );

    EXPECT_EQ( SF_SUCCESS( rootNode.PutNode( pArrayNode1 ) ), 0 );
    CPPUNIT_ASSERT( rootNode.Size() == 2 );

    SfJSONNode* pGetNode1 = NULL;
    EXPECT_EQ( SF_SUCCESS( rootNode.GetNode( nodeName, (SfJSONBase*&)pGetNode1 ) ), 0 );
    CPPUNIT_ASSERT( NULL != pGetNode1 );
    CPPUNIT_ASSERT( nodeName == pGetNode1->GetName() );

    SfJSONArrayNode* pGetArrayNode1 = NULL;
    EXPECT_EQ( SF_SUCCESS( rootNode.GetNode( arrayNodeName, (SfJSONBase*&)pGetArrayNode1 ) ), 0 );
    CPPUNIT_ASSERT( NULL != pGetArrayNode1 );
    CPPUNIT_ASSERT( arrayNodeName == pGetArrayNode1->GetName() );

    pGetNode1       = NULL;
    pGetArrayNode1  = NULL;
    EXPECT_EQ( SF_SUCCESS( rootNode.GetNode( 0, (SfJSONBase*&)pGetNode1 ) ), 0 );
    CPPUNIT_ASSERT( NULL != pGetNode1 );
    CPPUNIT_ASSERT( nodeName == pGetNode1->GetName() );

    EXPECT_EQ( SF_SUCCESS( rootNode.GetNode( 1, (SfJSONBase*&)pGetArrayNode1 ) ), 0 );
    CPPUNIT_ASSERT( NULL != pGetArrayNode1 );
    CPPUNIT_ASSERT( arrayNodeName == pGetArrayNode1->GetName() );
}

/**
****************************************************************************************************
//@sut      TestNodePutGetValue
//@brief    Fill value node to json
****************************************************************************************************
*/
void SfNodeJSONTest::TestNodePutGetValue()
{
    SfJSONNode node;
    std::string stringValue;
    node.Put( c_stringAttr, c_stringValue );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_stringAttr, stringValue ) ) , 0);
    CPPUNIT_ASSERT( c_stringValue == stringValue );

    std::string nullValue;
    node.Put( c_nullAttr, c_nullValue );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_nullAttr, nullValue ) ) , 0);
    CPPUNIT_ASSERT( c_nullValue == nullValue );

    Uint8 uint8Value = 0;
    node.Put( c_Uint8Attr, c_Uint8Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Uint8Attr, uint8Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint8Value == uint8Value );

    Uint16 uint16Value = 0;
    node.Put( c_Uint16Attr, c_Uint16Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Uint16Attr, uint16Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint16Value == uint16Value );

    Uint32 uint32Value = 0;
    node.Put( c_Uint32Attr, c_Uint32Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Uint32Attr, uint32Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint32Value == uint32Value );

    Uint64 uint64Value = 0;
    node.Put( c_Uint64Attr, c_Uint64Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Uint64Attr, uint64Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint64Value == uint64Value );

    Int8 int8Value = 0;
    node.Put( c_Int8Attr, c_Int8Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Int8Attr, int8Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int8Value == int8Value );

    Int16 int16Value = 0;
    node.Put( c_Int16Attr, c_Int16Value );
    EXPECT_EQ( SF_SUCCESS( node.Get( c_Int16Attr, int16Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int16Value == int16Value );

    Int32 int32Value = 0;
    node.Put( c_Int32Attr, c_Int32Value );
    CPPUNIT_ASSERT( SF_SUCCESS( node.Get( c_Int32Attr, int32Value ) ) );
    CPPUNIT_ASSERT( c_Int32Value == int32Value );

    Int64 int64Value = 0;
    node.Put( c_Int64Attr, c_Int64Value );
    CPPUNIT_ASSERT( SF_SUCCESS( node.Get( c_Int64Attr, int64Value ) ) );
    CPPUNIT_ASSERT( c_Int64Value == int64Value );

    bool boolTrue = false;
    node.Put( c_boolAttrTrue, c_boolTrueValue );
    CPPUNIT_ASSERT( SF_SUCCESS( node.Get( c_boolAttrTrue, boolTrue ) ) );
    CPPUNIT_ASSERT( c_boolTrueValue == boolTrue );

    bool boolFalse = true;
    node.Put( c_boolAttrFalse, c_boolFalseValue );
    CPPUNIT_ASSERT( SF_SUCCESS( node.Get( c_boolAttrFalse, boolFalse ) ) );
    CPPUNIT_ASSERT( c_boolFalseValue == boolFalse );
}

/**
****************************************************************************************************
//@sut      TestArrayNodePutGetValue
//@brief    Fill array node to json
****************************************************************************************************
*/
void SfNodeJSONTest::TestArrayNodePutGetValue()
{
    SfJSONArrayNode arrayNode( "arrayNode" );
    std::string stringValue;
    arrayNode.Put( c_stringValue );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 0, stringValue ) ) , 0);
    CPPUNIT_ASSERT( c_stringValue == stringValue );

    std::string nullValue;
    arrayNode.Put( c_nullValue );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 1, nullValue ) ) , 0);
    CPPUNIT_ASSERT( c_nullValue == nullValue );

    Uint8 uint8Value = 0;
    arrayNode.Put( c_Uint8Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 2, uint8Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint8Value == uint8Value );

    Uint16 uint16Value = 0;
    arrayNode.Put( c_Uint16Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 3, uint16Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint16Value == uint16Value );

    Uint32 uint32Value = 0;
    arrayNode.Put( c_Uint32Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 4, uint32Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint32Value == uint32Value );

    Uint64 uint64Value = 0;
    arrayNode.Put( c_Uint64Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 5, uint64Value ) ) , 0);
    CPPUNIT_ASSERT( c_Uint64Value == uint64Value );

    Int8 int8Value = 0;
    arrayNode.Put( c_Int8Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 6, int8Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int8Value == int8Value );

    Int16 int16Value = 0;
    arrayNode.Put( c_Int16Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 7, int16Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int16Value == int16Value );

    Int32 int32Value = 0;
    arrayNode.Put( c_Int32Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 8, int32Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int32Value == int32Value );

    Int64 int64Value = 0;
    arrayNode.Put( c_Int64Value );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 9, int64Value ) ) , 0);
    CPPUNIT_ASSERT( c_Int64Value == int64Value );

    bool boolTrue = false;
    arrayNode.Put( c_boolTrueValue );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 10, boolTrue ) ) , 0);
    CPPUNIT_ASSERT( c_boolTrueValue == boolTrue );

    bool boolFalse = true;
    arrayNode.Put( c_boolFalseValue );
    EXPECT_EQ( SF_SUCCESS( arrayNode.Get( 11, boolFalse ) ) , 0);
    CPPUNIT_ASSERT( c_boolFalseValue == boolFalse );

    CPPUNIT_ASSERT( 12 == arrayNode.Size() );
}

/**
****************************************************************************************************
//@sut      BuildDefaultNode
//@brief    Add Json value items 
//@input    SfJSONNode read json file
****************************************************************************************************
*/
void SfNodeJSONTest::BuildDefaultNode( SfJSONNode& node )
{
    node.Put( c_stringAttr, c_stringValue );
    node.Put( c_Uint8Attr,  c_Uint8Value );
    node.Put( c_Uint16Attr, c_Uint16Value );
    node.Put( c_Uint32Attr, c_Uint32Value );
    node.Put( c_Uint64Attr, c_Uint64Value );
    node.Put( c_Int8Attr,   c_Int8Value );
    node.Put( c_Int16Attr,  c_Int16Value );
    node.Put( c_Int32Attr,  c_Int32Value );
    node.Put( c_Int64Attr,  c_Int64Value);
    node.Put( c_boolAttrTrue,   c_boolTrueValue );
    node.Put( c_nullAttr,   c_nullValue );
}

/**
****************************************************************************************************
//@sut      BuildDefaultSimpleArrayNode
//@brief    Add Json Array items 
//@input    SfJSONArrayNode read json file
****************************************************************************************************
*/
void SfNodeJSONTest::BuildDefaultSimpleArrayNode( SfJSONArrayNode& node )
{
    node.Put( c_Uint8Value );
    node.Put( c_Uint16Value );
    node.Put( c_Uint32Value );
    node.Put( c_Uint64Value );
    node.Put( c_Int8Value );
    node.Put( c_Int16Value );
    node.Put( c_Int32Value );
    node.Put( c_Int64Value );
    node.Put( c_boolFalseValue );
    node.Put( c_stringValue );
    node.Put( c_nullValue );
}

