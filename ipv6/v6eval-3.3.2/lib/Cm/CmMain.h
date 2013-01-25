/*
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
 * Yokogawa Electric Corporation, YDC Corporation,
 * IPA (Information-technology Promotion Agency, Japan).
 * All rights reserved.
 * 
 * Redistribution and use of this software in source and binary forms, with 
 * or without modification, are permitted provided that the following 
 * conditions and disclaimer are agreed and accepted by the user:
 * 
 * 1. Redistributions of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in the 
 * documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the names of the copyrighters, the name of the project which 
 * is related to this software (hereinafter referred to as "project") nor 
 * the names of the contributors may be used to endorse or promote products 
 * derived from this software without specific prior written permission.
 * 
 * 4. No merchantable use may be permitted without prior written 
 * notification to the copyrighters. However, using this software for the 
 * purpose of testing or evaluating any products including merchantable 
 * products may be permitted without any notification to the copyrighters.
 * 
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHTERS, THE PROJECT AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING 
 * BUT NOT LIMITED THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.  IN NO EVENT SHALL THE 
 * COPYRIGHTERS, THE PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT,STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $TAHI: v6eval/lib/Cm/CmMain.h,v 1.9 2009/08/27 00:10:04 akisada Exp $
 */
#ifndef _Cm_CmMain_h_
#define _Cm_CmMain_h_	1
/* Interface Definition */
#include "CmTypes.h"
#include "BtList.h"
typedef void (*exitHandler)(int);
//======================================================================
// CmMain: �ץ����γ��Ϥ���ӽ�λ����
// C/C++�Υץ�����main()�ؿ��ǽ��������Ϥ����exit()�ؿ��ǽ�����λ����
//----------------------------------------------------------------------
// (1) �������
// CmMain�ϡ�main()���Ϥ��줿�Ķ����ݻ����롢�ʲ��ξ�����󶡤���
//	��ư���ΰ���
//	��ư���δĶ��ѿ�
//	��ư���ޥ��̾
//	��ư����/��ư�ץ����̾/��ư�桼��̾���㳲���Ͼ���
// �ʤ����嵭�㳲���Ͼ����core���ϻ���what�ǻ��Ȳ�ǽ�Ȥʤ�
// �����ƥ�˶��̤��ͤȤ���ɬ�פʾ�����󶡤���
//	�ץ����������ץ�Ǥ���ե�����κ�����
//	�ۥ���̾
// �ʤ���ɬ�פ˱�����¾�Υ����ƥ������ɲò�ǽ�Ǥ���
// �ޤ����Ķ��ѿ��ʤɤⶦ�̤˼�갷�����ͤˤ���Τ�˾�ޤ���
//----------------------------------------------------------------------
// (2) ��λ����
// ��λ�����ؿ�����Ͽ����Ӽ�ư�ƤӽФ�
//	��λ������ɬ�פʾ�硢�ؿ�����Ͽ��Ԥ�
//	��) ���ѥ���β���...
// �����ƥ�㳲���μ�ư��ư
//----------------------------------------------------------------------
// (3) �����ʥ����
// �ץ�������ߤ��뤹�٤ƤΥ����ʥ����ª���졢�㳲ȯ�������ɽ������
//----------------------------------------------------------------------
// (4) ������ˡ
// ���ץꥱ�������Υᥤ��ؿ��Ǥϡ�void applicationMain(CmMain*)��
// ���˽������ץꥱ�������ᥤ��ε��Ҥ�Ԥ���
// ���Ҥ��ưפˤ��뤿��applMain()�ޥ�����Ѱդ��Ƥ��롣
//----------------------------------------------------------------------
// (5) ������
// #include "CmMain.h"
// void callMeWhenExit(int i) {
//	...}
// someFunction() {
//	...
//	exit(1);}				// exit�ؿ��λ��Ѥ����¤����
// applMain() {
//	atexit(callMeWhenExit);	// ʣ����Ͽ��ǽ
//	int argc=main->argc();
//	STR *argv=main->argv();
//	...
//	}
//----------------------------------------------------------------------
// (6) �㳲�����Ͼ������
// % what core | grep START
// 96/06/19 12:20:29 t1array STARTED by tamura@alps on
// pty/ttyvc:tamura from dog:0.0
// ��ư���� �ץ����̾ STARTED by ��ư�桼��@��ư�ޥ��� on
// ttyname:������桼��̾ from ��⡼�ȥޥ���̾
//----------------------------------------------------------------------
struct CmMain {
private:
static	STR applicationName_;		// ��ư���ޥ��̾
static	char catchStart_[256];		// �㳲���Ͼ���
	int argCount_;			// ��ư�����ο�
	STR *orgArgs_;			// ��ư����
	STR *saveArgs_;			// ��ư������ʣ��
	STR *saveEnvp_;			// �Ķ��ѿ�
static	CmMain* instance_;
public:
static	CmMain* instance();
	~CmMain();
	CmMain(int argc,STR *argv,STR *envp);
//----------------------------------------------------------------------
// ��ư������
	int argc() const;
	STR*argv() const;
	STR applicationName(STR pgm=0);
	const STR command() const;
	const STR* const saveArguments() const;
	const STR catchEyeStart() const;
static	void setDbgFlags(CSTR);
//----------------------------------------------------------------------
// �����ƥ����
	const int getdtablesize();
	const STR myHostname();
//----------------------------------------------------------------------
// ��λ����
	void restart();
private:
//----------------------------------------------------------------------
// �����ؿ�
	void save(int);
	void makeCatch2Eye(STR);
	void makeCatchEye(const STR);
	const STR *saveArgs() const;
	const STR *saveEnvp() const;
};
extern char dbgFlags[];
extern uint32_t logLevel;
extern bool DoHexDump;
#define applMain() void applicationMain(CmMain* main) 
//----------------------------------------------------------------------
// inline�ؿ�
inline	CmMain* CmMain::instance() {return instance_;}
inline	int CmMain::argc() const {return argCount_;}
inline	STR*CmMain::argv() const {return orgArgs_;}
inline	const STR CmMain::catchEyeStart() const	{return catchStart_;}
inline	const STR CmMain::command() const 	{return saveArgs_[0];}
inline	const STR*CmMain::saveArgs() const 	{return saveArgs_;}
inline	const STR*CmMain::saveEnvp() const 	{return saveEnvp_;}
inline	const STR* const CmMain::saveArguments() const 	{return saveArgs_;}

#ifndef DBGFLAGS
// avoid warning of compilation
//     gcc version 3.3.1 [FreeBSD]
//     warning: array subscript has type `char'
#define DBGFLAGS(c)	(dbgFlags[(int)(c)])
#endif	// DBGFLAGS
#endif
