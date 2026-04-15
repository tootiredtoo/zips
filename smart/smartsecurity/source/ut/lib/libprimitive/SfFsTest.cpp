/**
****************************************************************************************************
* @file SfFsTest.cpp
* @brief Security framework [SF] implementation: libprimitive is tested
* @author Viacheslav Vovchenko (v.vovchenko@samsung.com)
* @date November 27, 2014 18:00.
* @see VD Coding standard guideline [VDSW-IMC-GDL02] 5.4 release 2013-08-12
* @par In Samsung Ukraine R&D Center (SURC) under a contract between
* @par LLC "Samsung Electronics Ukraine Company" (Kiev, Ukraine)
* @par and "Samsung Electronics Co", Ltd (Seoul, Republic of Korea)
* @par Copyright: (c) Samsung Electronics Co, Ltd 2014. All rights reserved.
****************************************************************************************************
*/

// project
#include "libprimitive/SfFs.h"
// third party
#include <gtest/gtest.h>
#include <string.h>
#include <fstream>
#include <iostream>
// namespaces
using namespace std;

/**
****************************************************************************************************
* @class SfFs_TestSuite
* @brief C++  File system tests the implementation
* @todo	Portable support
****************************************************************************************************
*/
class SfFs_TestSuite: public testing::Test
{
protected:

	/**
	****************************************************************************************************
	* @brief Called before the first test in this test case
	****************************************************************************************************
	*/
	static void SetUpTestCase()
	{
		//SfOpenDebuggerContext(NULL);
	}

	/**
	****************************************************************************************************
	* @brief Per-test set-up
	****************************************************************************************************
	*/
	virtual void SetUp()
	{
		ClearAll();
	}

	/**
	****************************************************************************************************
	* @brief Per-test tear-down
	****************************************************************************************************
	*/
	virtual void TearDown()
	{
		ClearAll();
	}

	/**
	****************************************************************************************************
	* @brief Function removes all temporary files and folders which used to tests
	****************************************************************************************************
	*/
	static int ClearAll()
	{
		int r = 0;
		r = remove( sFileNameFirst.c_str() );
		r = remove( sFileNameSecond.c_str() );
		//Disable output console
		cout.clear( ios_base::badbit );
		//Clear old files if it exists
		r = system(sFilesRemoveCmd.c_str());
		//Clear old folder if it exists
		r = system(sFolderRemoveCmd.c_str());
		//Enable output console
		cout.clear( ios_base::goodbit );
		return r;
	}

	/**
	****************************************************************************************************
	* @brief Function creates some files use to tests
	* @param	[in] Name of file to create
	* @return   True on success, false otherwise
	****************************************************************************************************
	*/
	bool CreateTemporaryFile(const string& sName)
	{
		ofstream file(sName.c_str());
		bool bOpen = file.is_open();
		if(bOpen)
		{
			file << "Test";
			file.close();
		}
		return bOpen;
	}

	/**
	****************************************************************************************************
	* @brief Function compares 2 files use to tests
	* @param	[in] Name of file1
	* @param	[in] Name of file2
	* @return   True on success, false otherwise
	****************************************************************************************************
	*/
	bool CompareFiles(const string& sName1, const string& sName2)
	{
		bool 		bRes = false, bEqualFiles = true;
		ifstream 	file1(sName1.c_str()),
					file2(sName2.c_str());
		do
		{
			if(!file1.is_open() || !file2.is_open())
				break;
			string sLine1, sLine2;

			//continue you get till the end of both
			while ((!file1.eof()) && (!file1.eof()))
			{
				//get lines from files
				getline(file1, sLine1);
				getline(file2, sLine2);

				//compare two strings
				if(sLine1 != sLine2)
				{
					bEqualFiles = false;
					break;
				}
			}

			bRes = bEqualFiles;

		} while(0);

		if(file1.is_open())
			file1.close();
		if(file2.is_open())
			file2.close();

		return bRes;
	}

protected: // members

	static const string sFileNameFirst;		//!< Name of file 1
	static const string sFileNameSecond;	//!< Name of file 2
	static const string sFilesRemoveCmd;	//!< Command removes the files

	static const string sDirName;			//!< Name of folder
	static const string sFolderRemoveCmd;	//!< Command removes the directory
};

//static declarations
//for files
const string SfFs_TestSuite::sFileNameFirst 	= 	"test";
const string SfFs_TestSuite::sFileNameSecond 	= 	sFileNameFirst + "_new";
const string SfFs_TestSuite::sFilesRemoveCmd	= 	"rm ./" + sFileNameFirst +
													"./" + sFileNameSecond +
													">/dev/null 2>/dev/null";
//for folders
const string SfFs_TestSuite::sDirName 			= 	"test_folder";
const string SfFs_TestSuite::sFolderRemoveCmd	= 	"rm -r ./" +
													sDirName +
													">/dev/null 2>/dev/null";

/**
***************************************************************************************************
//@sut      vdapi_SfFsUtilFileUseTest_p SfFs_TestSuite
//@brief    Test the operations utility for files
//@input    sFileNameFirst
***************************************************************************************************
*/
TEST_F(SfFs_TestSuite, vdapi_SfFsUtilFileUseTest_p)
{
	//Create temporary file used to tests
	EXPECT_TRUE( true == CreateTemporaryFile(sFileNameFirst) );

	//checking rename file
	EXPECT_TRUE( true == RenameFile(sFileNameFirst, sFileNameSecond) );
	//checking new name file
	EXPECT_TRUE( true 	== FileExists(sFileNameSecond) );
	//checking old file should be not exist
	EXPECT_TRUE( false 	== FileExists(sFileNameFirst) );

	//Testing copy files
	EXPECT_TRUE( true 	== CopyFile(sFileNameSecond, sFileNameFirst) );
	EXPECT_TRUE( true 	== FileExists(sFileNameFirst) );
	//Compare files
	EXPECT_TRUE( true 	== CompareFiles(sFileNameFirst, sFileNameSecond) );

	//Testing delete files
	EXPECT_TRUE( true 	== DeleteFile(sFileNameFirst) );
	EXPECT_TRUE( false 	== FileExists(sFileNameFirst) );

	EXPECT_TRUE( true 	== DeleteFile(sFileNameSecond) );
	EXPECT_TRUE( false 	== FileExists(sFileNameSecond) );
}

/**
***************************************************************************************************
//@sut      vdapi_SfFsUtilFolderUsetest_p SfFs_TestSuite
//@brief    Test the operations utility for folders positive Test
//@input    SfFilesList
***************************************************************************************************
*/
TEST_F(SfFs_TestSuite, vdapi_SfFsUtilFolderUsetest_p)
{
    const Uint64 numFiles = 5;
	SfFilesList lstFiles;

	//Testing folder
	EXPECT_TRUE( true 	== CreateFolder(sDirName) );
	EXPECT_TRUE( true 	== FolderExists(sDirName) );
	EXPECT_TRUE( false 	== GetAbsolutePath(sDirName).empty() );

    for(Uint64 i = 0; i < numFiles; ++i)
	{
		ostringstream oss;
		oss << sFileNameFirst << "_" << i;
		lstFiles.push_back(oss.str());
		CreateTemporaryFile(sDirName + "/" + oss.str());
	}
	//Checking number files
    //EXPECT_EQ( numFiles, CountFilesRecursive(sDirName) );

	//GetAbsolutePath
	string sAbsPath = GetAbsolutePath("../");
	bool bIsAbsPath = !sAbsPath.empty();
	EXPECT_TRUE( bIsAbsPath );
	if(bIsAbsPath)
	{
		EXPECT_EQ ( '/', sAbsPath[0] );
	}

	//todo FixDirectoryPath
}
