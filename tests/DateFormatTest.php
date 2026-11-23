<?php

// This covers the translation of strftime()-style DATETIME_FORMAT and
// DATEONLY_FORMAT values into date()-style formats (strftime() and strptime()
// are deprecated since PHP 8.1).
class DateFormatTest extends RTTestCase
{
	protected static $old_format;
	protected static $old_tz;
	const TS = 1700000000; // Tue, 14 Nov 2023 22:13:20 UTC

	public static function setUpBeforeClass () : void
	{
		self::$old_format = getConfigVar ('DATETIME_FORMAT');
		self::$old_tz = date_default_timezone_get();
		date_default_timezone_set ('UTC');
	}

	public static function tearDownAfterClass () : void
	{
		setConfigVar ('DATETIME_FORMAT', self::$old_format);
		date_default_timezone_set (self::$old_tz);
	}

	/**
	 * @group small
	 * @dataProvider providerFormats
	 */
	public function testFormat ($strftime_format, $expected)
	{
		$this->assertSame ($expected, date (dateFormatFromStrftimeFormat ($strftime_format), self::TS));
	}

	public function providerFormats ()
	{
		return array
		(
			array ('%Y-%m-%d', '2023-11-14'),
			array ('%d.%m.%Y %H:%M', '14.11.2023 22:13'),
			array ('%a, %d %b %Y %T 100%%', 'Tue, 14 Nov 2023 22:13:20 100%'),
			array ('%D %r', '11/14/23 10:13:20 PM'),
		);
	}

	/**
	 * @group small
	 * @dataProvider providerRoundTrip
	 */
	public function testRoundTrip ($strftime_format)
	{
		setConfigVar ('DATETIME_FORMAT', $strftime_format);
		$s = datetimestrFromTimestamp (self::TS);
		$this->assertSame ($s, datetimestrFromTimestamp (timestampFromDatetimestr ($s)));
	}

	public function providerRoundTrip ()
	{
		return array
		(
			array ('%Y-%m-%d %H:%M:%S'),
			array ('%d/%m/%Y %H:%M'),
			array ('%Y-%m-%d'),
		);
	}

	/**
	 * @group small
	 */
	public function testSQLDateFromDateStr ()
	{
		$this->assertSame ('2023-02-01', SQLDateFromDateStr ('1/2/2023', '%d/%m/%Y'));
	}
}
