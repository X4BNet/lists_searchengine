<?php
require 'vendor/autoload.php';

/**
 * Class for manipulating IP lists and CIDR lists
 *
 */
class IPListCIDR
{
	/**
	 * Convert a list of IPv4 addresses (or numbers) into a list of ranges
	 *
	 * @param int[] $ips array of sorted IPv4 addresses as integers
	 * @return int[]
	 */
	function ip_to_range($ips, $sorted = false)
	{
	    if(!$sorted) {
            $ips = array_values($ips);
            sort($ips);
        }

        if((is_array($ips) || $ips instanceof \Countable) && count($ips) <= 2) {
            return $ips;
        }


	    $s = null;
		$ret = array();
        if(is_array($ips)){
            $ips = new \ArrayIterator($ips);
        }
		while($current = $ips->current()) {
			$ips->next();
            $next = $ips->current();

			if ($next !== false && $current + 1 == $next) {
                if($s === null) $s = $current;
            }else{
			    if($s)
			    {
			        $ret[] = array($s, $current);
			        $s = null;
                }
                else
                {
                    $ret[] = $current;
                }
            }
		}

		return $ret;
	}

	/**
	 * Convert a list of IPv4 addresses into a list of CIDRs
	 *
	 * @param int[] $ips IPv4 addresses in long form
	 * @return string[] an array of CIDR's and IP addresses that would contain all the supplied IPs
	 */
	public function to_cidr_list($ips, $short_syntax = true, $sorted = false)
	{
		$ip_ranges = $this->ip_to_range($ips, $sorted);

		$cidrs = array();
		foreach ($ip_ranges as $range) {
			if (!is_array($range)) {
                if(strpos($range, '/') !== false) {
                    continue;
                }
				$ip = \PhpIP\IP::create($range);
				$cidrs[] = (string)$ip;
			} else {
				$range[0] = \PhpIP\IP::create($range[0]);
				$range[1] = \PhpIP\IP::create($range[1]);
				foreach (CIDRRange::rangeToCIDRList((string)$range[0],(string)$range[1], $short_syntax) as $c) {
					$cidrs[] = $c;
				}
			}
		}

		return $cidrs;
	}

	/**
	 * Convert a list of CIDRs into a list of IPv4 addresses (number format)
	 *
	 * @param $ips
	 */
	public function cidr2long(&$ips, $targetVersion = 4)
	{
		foreach ($ips as $k => $v) {
            $ips[$k] = $v = trim($v);
			if (strpos($v, '/') || $v instanceof \PhpIP\IPBlock) {
				try {
					$v = ($v instanceof \PhpIP\IPBlock) ? $v : \PhpIP\IPBlock::create($v);
				}catch (\Exception $ex){
					continue;
				}
                if($targetVersion && $v->getVersion() != $targetVersion) {
                    unset($ips[$k]);
                    continue;
                }
				foreach ($v as $kk => $i) {
					if ($kk == 0) {
						$ips[$k] = $i->numeric();
					} else {
						$ips[] = $i->numeric();
					}
				}
			} else {
				try {
					$ips[$k] = \PhpIP\IP::create($v)->numeric();
				}catch (\Exception $ex){
					continue;
				}
			}
		}
	}

    /**
     * Convert a list of CIDRs into a list of IPv4 addresses (number format)
     *
     * @param $ips
     */
    public function cidr2longGenerator($ips, $sorted = false)
    {
        foreach ($ips as $k => $v) {
            if (strpos($v, '/') || $v instanceof \PhpIP\IPBlock) {
                try {
                    $v = ($v instanceof \PhpIP\IPBlock) ? $v : \PhpIP\IPBlock::create($v);
                }catch (\Exception $ex){
                    continue;
                }
                if($sorted) {
                    foreach ($v as $kk => $i) {
                        if ($kk == 0) {
                            yield $i->numeric();
                        } else {
                            yield $i->numeric();
                        }
                    }
                }else{
                    $ips[$k] = $v;
                }
            } else {
                try {
                    $v = \PhpIP\IP::create($v);
                }catch (\Exception $ex){
                    continue;
                }
                if(!$sorted){
                    $ips[$k] = $v;
                }else{
                    yield $v->numeric();
                }
            }
        }
        if(!$sorted){
            $numeric = function($v){
                if($v instanceof \PhpIP\IPBlock){
                    return $v->getNetworkAddress()->numeric();
                }
                return $v->numeric();
            };
            usort($ips, function($a, $b) use($numeric){
                $a = $numeric($a);
                $b = $numeric($b);

                if($a < $b) return -1;
                if($b > $a) return 1;
                return 0;
            });

            foreach($ips as $v){
                if($v instanceof \PhpIP\IP){
                    yield $v->numeric();
                }else{
                    foreach ($v as $kk => $i) {
                        if ($kk == 0) {
                            yield $i->numeric();
                        } else {
                            yield $i->numeric();
                        }
                    }
                }
            }
        }
    }

	/**
	 * Lossy conversion to subnets of a specific $cidr as long as $number_req is met
	 *
	 * @param $ips
	 * @param $cidr
	 * @param $number_req
	 * @return string[] CIDR's containing the IPs removed from $ips
	 */
	public function subnet_reduce(&$ips, $cidr, $number_req)
	{
		$cidr24s = array();
		$ipmask = -1 << (32 - (int)$cidr);

		foreach ($ips as $k => $v) {
			$mask = $v & $ipmask;
			if (!isset($cidr24s[$mask])) $cidr24s[$mask] = 0;
			$m = ++$cidr24s[$mask];
			if ($m >= $number_req) unset($ips[$k]);
		}

		foreach($cidr24s as $k=>$v){
            if ($cidr24s[$k] < $number_req) unset($cidr24s[$k]);
        }

		foreach ($ips as $k => $v) {
			if (isset($cidr24s[$v & $ipmask])) unset($ips[$k]);
		}

		$append = '/' . $cidr;
		foreach ($cidr24s as $mk => $mv) {
            $cidr24s[$mk] = long2ip($mk) . $append;
        }

		return array_values($cidr24s);
	}
}


/**
 * CIDR.php
 *
 * Utility Functions for IPv4 ip addresses.
 *
 * @author Jonavon Wilcox <jowilcox@vt.edu>
 * @version Sat Jun  6 21:26:48 EDT 2009
 * @copyright Copyright (c) 2009 Jonavon Wilcox
 */
/**
 * class CIDR.
 * Holds static functions for ip address manipulation.
 */
class CIDRRange
{
    /**
     * method CIDRtoMask
     * Return a netmask string if given an integer between 0 and 32. I am
     * not sure how this works on 64 bit machines.
     * Usage:
     *     CIDR::CIDRtoMask(22);
     * Result:
     *     string(13) "255.255.252.0"
     * @param $int int Between 0 and 32.
     * @access public
     * @static
     * @return String Netmask ip address
     */
    public static function CIDRtoMask($int)
    {
        return long2ip(-1 << (32 - (int)$int));
    }

    /**
     * method countSetBits.
     * Return the number of bits that are set in an integer.
     * Usage:
     *     CIDR::countSetBits(ip2long('255.255.252.0'));
     * Result:
     *     int(22)
     * @param $int int a number
     * @access public
     * @static
     * @see http://stackoverflow.com/questions/109023/best-algorithm-to-co\
     * unt-the-number-of-set-bits-in-a-32-bit-integer
     * @return int number of bits set.
     */
    public static function countSetbits($int)
    {
        $int = $int - (($int >> 1) & 0x55555555);
        $int = ($int & 0x33333333) + (($int >> 2) & 0x33333333);
        return (($int + ($int >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
    }

    /**
     * method validNetMask.
     * Determine if a string is a valid netmask.
     * Usage:
     *     CIDR::validNetMask('255.255.252.0');
     *     CIDR::validNetMask('127.0.0.1');
     * Result:
     *     bool(true)
     *     bool(false)
     * @param $netmask String a 1pv4 formatted ip address.
     * @see http://www.actionsnip.com/snippets/tomo_atlacatl/calculate-if-\
     * a-netmask-is-valid--as2-
     * @access public
     * @static
     * @return bool True if a valid netmask.
     */
    public static function validNetMask($netmask)
    {
        $netmask = ip2long($netmask);
        $neg = ((~(int)$netmask) & 0xFFFFFFFF);
        return (($neg + 1) & $neg) === 0;
    }

    /**
     * method maskToCIDR.
     * Return a CIDR block number when given a valid netmask.
     * Usage:
     *     CIDR::maskToCIDR('255.255.252.0');
     * Result:
     *     int(22)
     * @param $netmask String a 1pv4 formatted ip address.
     * @throws \Exception
     * @access public
     * @static
     * @return int CIDR number.
     */
    public static function maskToCIDR($netmask)
    {
        if (self::validNetMask($netmask)) {
            $long = ip2long($netmask);
            $base = ip2long('255.255.255.255');
            return 32 - log(($long ^ $base) + 1, 2);
        } else {
            throw new \Exception('Invalid Netmask');
        }
    }

    /**
     * method alignedCIDR.
     * It takes an ip address and a netmask and returns a valid CIDR
     * block.
     * Usage:
     *     CIDR::alignedCIDR('127.0.0.1','255.255.252.0');
     * Result:
     *     string(12) "127.0.0.0/22"
     * @param $ipinput String a IPv4 formatted ip address.
     * @param $netmask String a 1pv4 formatted ip address.
     * @access public
     * @static
     * @return String CIDR block.
     */
    public static function alignedCIDR($ipinput, $netmask)
    {
        $alignedIP = long2ip((ip2long($ipinput)) & (ip2long($netmask)));
        return "$alignedIP/" . self::maskToCIDR($netmask);
    }

    /**
     * method IPisWithinCIDR.
     * Check whether an IP is within a CIDR block.
     * Usage:
     *     CIDR::IPisWithinCIDR('127.0.0.33','127.0.0.1/24');
     *     CIDR::IPisWithinCIDR('127.0.0.33','127.0.0.1/27');
     * Result:
     *     bool(true)
     *     bool(false)
     * @param $ipinput String a IPv4 formatted ip address.
     * @param $cidr String a IPv4 formatted CIDR block. Block is aligned
     * during execution.
     * @access public
     * @static
     * @return String CIDR block.
     */
    public static function IPisWithinCIDR($ipinput, $cidr)
    {
        $cidr = explode('/', $cidr);
        $cidr = self::alignedCIDR($cidr[0], self::CIDRtoMask((int)$cidr[1]));
        $cidr = explode('/', $cidr);
        $ipinput = (ip2long($ipinput));
        $ip1 = (ip2long($cidr[0]));
        $ip2 = ($ip1 + pow(2, (32 - (int)$cidr[1])) - 1);
        return (($ip1 <= $ipinput) && ($ipinput <= $ip2));
    }

    /**
     * method maxBlock.
     * Determines the largest CIDR block that an IP address will fit into.
     * Used to develop a list of CIDR blocks.
     * Usage:
     *     CIDR::maxBlock("127.0.0.1");
     *     CIDR::maxBlock("127.0.0.0");
     * Result:
     *     int(32)
     *     int(8)
     * @param $ipinput String a IPv4 formatted ip address.
     * @access public
     * @static
     * @return int CIDR number.
     */
    public static function maxBlock($ipinput)
    {
        return self::maskToCIDR(long2ip(-(ip2long($ipinput) & -(ip2long($ipinput)))));
    }

    /**
     * method rangeToCIDRList.
     * Returns an array of CIDR blocks that fit into a specified range of
     * ip addresses.
     * Usage:
     *     CIDR::rangeToCIDRList("127.0.0.1","127.0.0.34");
     * Result:
     *     array(7) {
     *       [0]=> string(12) "127.0.0.1/32"
     *       [1]=> string(12) "127.0.0.2/31"
     *       [2]=> string(12) "127.0.0.4/30"
     *       [3]=> string(12) "127.0.0.8/29"
     *       [4]=> string(13) "127.0.0.16/28"
     *       [5]=> string(13) "127.0.0.32/31"
     *       [6]=> string(13) "127.0.0.34/32"
     *     }
     * @param $startIPinput String a IPv4 formatted ip address.
     * @param integer|null $endIPinput
     * @see http://null.pp.ru/src/php/Netmask.phps
     * @return Array CIDR blocks in a numbered array.
     */
    public static function rangeToCIDRList($startIPinput, $endIPinput = NULL, $shorten = true)
    {
        $listCIDRs = array();
        $start = ip2long($startIPinput);
        $end = (empty($endIPinput)) ? $start : ip2long($endIPinput);
        while ($end >= $start) {
            $maxsize = self::maxBlock(long2ip($start));
            $maxdiff = 32 - intval(log($end - $start + 1) / log(2));
            $size = ($maxsize > $maxdiff) ? $maxsize : $maxdiff;
            $ip = long2ip($start);
            if($size != 32 && $shorten){
                $ip .= "/$size";
            }
            $listCIDRs[] = $ip;
            $start += pow(2, (32 - $size));
        }
        return $listCIDRs;
    }

    /**
     * method cidrToRange.
     * Returns an array of only two IPv4 addresses that have the lowest ip
     * address as the first entry. If you need to check to see if an IPv4
     * address is within range please use the IPisWithinCIDR method above.
     * Usage:
     *     CIDR::cidrToRange("127.0.0.128/25");
     * Result:
     *     array(2) {
     *       [0]=> string(11) "127.0.0.128"
     *       [1]=> string(11) "127.0.0.255"
     *     }
     * @param $cidr string CIDR block
     * @return Array low end of range then high end of range.
     */
    public static function cidrToRange($cidr)
    {
        $range = array();
        $cidr = explode('/', $cidr);
        $range[0] = long2ip((ip2long($cidr[0])) & ((-1 << (32 - (int)$cidr[1]))));
        $range[1] = long2ip((ip2long($cidr[0])) + pow(2, (32 - (int)$cidr[1])) - 1);
        return $range;
    }
}

$ilc = new IPListCIDR();
$ips = file("php://stdin");
$ilc->cidr2long($ips);

$out = array(
    $ilc->subnet_reduce($ips, 22, 400),
    $ilc->subnet_reduce($ips, 24, 150),
    $ilc->subnet_reduce($ips, 27, 17),
    $ilc->to_cidr_list($ips)
);
$ips = array_merge(...$out);

foreach($ips as $ip){
    if(strpos($ip, ':')) continue;
    echo $ip,"\n";
}