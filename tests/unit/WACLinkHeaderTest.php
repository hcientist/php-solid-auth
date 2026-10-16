<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;

/**
 * The `Link: <…>; rel="acl"` header every response carries.
 *
 * - Web Access Control 1.0.0, §3.1 ACL Resource Discovery
 *   (https://solidproject.org/TR/2024/wac-20240512#server-link-acl): the server
 *   "MUST advertise the ACL resource" with a Link header whose rel is acl, and
 *   "MUST NOT directly associate more than one ACL resource to a resource"
 *   (#server-resource-acl-max).
 * - Solid Protocol 0.11.0, §4.3 Auxiliary Resources
 *   (https://solidproject.org/TR/2024/protocol-20240512#server-link-auxiliary-type)
 *   and §11.1 Web Access Control (#web-access-control): the acl link relation
 *   associates a resource with its own ACL resource.
 * - Web Access Control 1.0.0, §5.1 Effective ACL Resource
 *   (#effective-acl-resource-algorithm): the resource's own ACL is used when it
 *   has a representation, otherwise the container's.
 *
 * Regression: documents were sent `<.acl>`, which resolves to their container's
 * ACL, so a client changing access to one document rewrote the whole folder's.
 *
 * @coversDefaultClass \Pdsinterop\Solid\Auth\WAC
 * @covers ::addWACHeaders
 */
class WACLinkHeaderTest extends AbstractTestCase
{
    private const OWNER = 'https://example.com/profile/card#me';

    /** @param array<string, string> $files path => Turtle */
    private function linkAndAllow(string $url, array $files = []): array
    {
        $filesystem = new class($files) {
            public function __construct(private array $files) {}
            public function fileExists($path) { return isset($this->files[$path]); }
            public function read($path) { return $this->files[$path] ?? false; }
        };
        $adapter = new class {
            private $format = '';
            public function getFormat() { return $this->format; }
            public function setFormat($format) { $this->format = $format; }
        };
        $wac = new WAC($filesystem, $adapter);
        $wac->setBaseUrl('https://example.com');
        $response = $wac->addWACHeaders(new ServerRequest([], [], $url, 'GET'), new Response(), self::OWNER);

        return [$response->getHeaderLine('Link'), $response->getHeaderLine('WAC-Allow')];
    }

    private static function acl(string $accessTo, string $mode): string
    {
        return '@prefix acl: <http://www.w3.org/ns/auth/acl#> .' . "\n"
            . '<#owner> a acl:Authorization ; acl:agent <' . self::OWNER . '> ;'
            . " acl:accessTo <$accessTo> ; acl:mode acl:$mode .\n";
    }

    /** @testdox A document advertises its own ACL, beside it (WAC §3.1 #server-link-acl) */
    public function testDocumentAdvertisesItsOwnAcl(): void
    {
        [$link] = $this->linkAndAllow('https://example.com/wardrobe/alice.ttl');
        $this->assertSame('<alice.ttl.acl>; rel="acl"', $link);
    }

    /** @testdox A container advertises the .acl inside it (WAC §3.1 #server-link-acl) */
    public function testContainerAdvertisesDotAcl(): void
    {
        [$link] = $this->linkAndAllow('https://example.com/wardrobe/');
        $this->assertSame('<.acl>; rel="acl"', $link);
    }

    /** @testdox The advertised link is a valid relative reference for any document name */
    public function testDocumentNameIsEncoded(): void
    {
        [$link] = $this->linkAndAllow('https://example.com/wardrobe/two%20words.ttl');
        $this->assertSame('<two%20words.ttl.acl>; rel="acl"', $link);
    }

    /**
     * @testdox The advertised ACL is the one the server enforces for that document (WAC §5.1, #server-resource-acl-max)
     *
     * With a document ACL that grants Read and a container ACL that grants Write,
     * the server applies the document's; the Link header must name that one.
     */
    public function testAdvertisedAclIsTheEnforcedOne(): void
    {
        [$link, $allow] = $this->linkAndAllow('https://example.com/wardrobe/alice.ttl', [
            '/wardrobe/alice.ttl.acl' => self::acl('https://example.com/wardrobe/alice.ttl', 'Read'),
            '/wardrobe/.acl' => self::acl('https://example.com/wardrobe/', 'Write'),
        ]);

        $this->assertSame('user="read"', $allow, 'the document ACL is the one in force');
        // <alice.ttl.acl> resolved against /wardrobe/alice.ttl is /wardrobe/alice.ttl.acl.
        $this->assertSame('<alice.ttl.acl>; rel="acl"', $link);
    }
}
