/**************************************************************************\
*                                                                          *
*   Copyright (C) 2021-2024 Neo-Mind                                       *
*                                                                          *
*   This file is a part of WARP project                                    *
*                                                                          *
*   WARP is free software: you can redistribute it and/or modify           *
*   it under the terms of the GNU General Public License as published by   *
*   the Free Software Foundation, either version 3 of the License, or      *
*   (at your option) any later version.                                    *
*                                                                          *
*   This program is distributed in the hope that it will be useful,        *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
*   GNU General Public License for more details.                           *
*                                                                          *
*   You should have received a copy of the GNU General Public License      *
*   along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
*                                                                          *
*                                                                          *
|**************************************************************************|
*                                                                          *
*   Author(s)     : Neo-Mind                                               *
*   Created Date  : 2021-08-20                                             *
*   Last Modified : 2024-08-01                                             *
*                                                                          *
\**************************************************************************/

//
// Stores the server type
// =========================
//
// MODULE_NAME => SRVRTYPE
// -----------------------

///
/// \brief Local data members
///
const self = 'SRVRTYPE';

/**Will be true or false indicating extraction status**/
var Valid;

/**Will contain the Error Object with a message about the issue encountered during extraction if any**/
var ErrMsg;

/**The g_serverType VIRTUAL Address**/
var Value;

/**It's hex in Little Endian form**/
var Hex;

///
/// \brief Initialization Function
///
export function init()
{
	Value  = -1;
	Hex    = '';
	Valid  = null;
	ErrMsg = null;

	Identify(self, ['init', 'load', 'toString', 'valueOf']);
}

///
/// \brief Function to extract data from loaded exe and set the members
///
export function load()
{
	const _ = Log.dive(self, 'load');

	$$(_, 1.1, `Check if load was already called`)
	if (Valid != null)
	{
		$$(_, 1.2, `Check for errors and report them again if present otherwise simply return`)
		Log.rise();

		if (Valid)
			return Valid;
		else
			throw ErrMsg;
	}

	$$(_, 1.3, `Initialize [Valid] to false`)
	Valid = false;

	$$(_, 1.4, `Find the string 'sakray'`)
	let addr = Exe.FindText("sakray");
	if (addr > 0)
	{
		$$(_, 1.5, `Find where it is PUSHed`)
		addr = Exe.FindHex( PUSH(addr) );
		if (addr < 0)
			throw Log.rise(ErrMsg = new Error(`${self} - 'sakray' not used`));

		$$(_, 1.6, `Move addr to location after PUSH`)
		addr += 5;
	}
	else if (ROC.FullVer == 14.29)
	{
		$$(_, 2.1, `Find the string 'sakray' compared in parts`)
		const code =
			CMP([R32], 0x726B6173)          //cmp dword ptr [regA], 73616B72h ; 'sakr'
		+	JNE(WCp)                        //jne short _skip
		+	CMP(WORD_PTR, [R32, 4], 0x7961) //cmp word ptr [regA + 4], 7961h  ; 'ay'
		+	JNE(WCp)                        //jne short _skip
		;

		addr = Exe.FindHex(code);
		if (addr < 0)
			throw Log.rise(ErrMsg = new Error(`${self} - 'sakray' not found in parts`));

		$$(_, 2.2, `Move addr to location after the code`)
		addr += code.byteCount();
	}
	else
	{
		throw Log.rise(ErrMsg = new Error(`${self} - 'sakray' not found`));
	}

	$$(_, 3.1, `Find an assignment to g_serverType after it`)
	addr = Exe.FindHex( MOV([POS4WC], 1), addr); //mov dword ptr [g_serverType], 1
	if (addr < 0)
		throw Log.rise(ErrMsg = new Error(`${self} - g_serverType not assigned`));

	$$(_, 3.2, `Extract the address to [Value] & save it's hex`)
	Value = Exe.GetUint32(addr + 2);
	Hex   = Value.toHex(4);

	$$(_, 3.3, `Set [Valid] to true`)
	return Log.rise(Valid = true);
}

///
/// \brief Override to return the hex value
///
export function toString()
{
	return Hex;
}

///
/// \brief Override to return the numeric value
///
export function valueOf()
{
	return Value;
}

///
/// \brief Tester
///
export function debug()
{
	if (Valid == null)
		load();

	if (Valid == null)
	{
		Info(self + ".ErrMsg = ", ErrMsg);
		return false;
	}
	else
	{
		ShowAddr(self, Value, VIRTUAL);
		return true;
	}
}