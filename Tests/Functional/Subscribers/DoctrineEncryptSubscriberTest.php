<?php


namespace Ambta\DoctrineEncryptBundle\Tests\Functional\Subscribers;


use Ambta\DoctrineEncryptBundle\Encryptors\HaliteEncryptor;
use Ambta\DoctrineEncryptBundle\Subscribers\DoctrineEncryptSubscriber;
use Ambta\DoctrineEncryptBundle\Tests\Functional\Subscribers\Entity\CascadeTarget;
use Doctrine\Common\Annotations\AnnotationReader;
use Doctrine\DBAL\Logging\DebugStack;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\ORM\Tools\Setup;
use PHPUnit\Framework\TestCase;
use Ambta\DoctrineEncryptBundle\Tests\Functional\Subscribers\Entity\Owner;

/**
 * @property EntityManager entityManager
 * @property false|string dbFile
 * @property DoctrineEncryptSubscriber subscriber
 * @property HaliteEncryptor encryptor
 */
class DoctrineEncryptSubscriberTest extends TestCase
{


    public function setUp()
    {
        // Create a simple "default" Doctrine ORM configuration for Annotations
        $isDevMode                 = true;
        $proxyDir                  = null;
        $cache                     = null;
        $useSimpleAnnotationReader = false;

        $config = Setup::createAnnotationMetadataConfiguration(
            array(__DIR__ . "/Entity"),
            $isDevMode,
            $proxyDir,
            $cache,
            $useSimpleAnnotationReader
        );

        // database configuration parameters
        $this->dbFile = tempnam(sys_get_temp_dir(), 'amb_db');
        $conn = array(
            'driver' => 'pdo_sqlite',
            'path'   => $this->dbFile,
        );

        // obtaining the entity manager
        $this->entityManager = EntityManager::create($conn, $config);

        $reader = new AnnotationReader();
        $keyfile = __DIR__.'/fixtures/halite.key';
        $this->encryptor = new HaliteEncryptor($keyfile);

        $this->subscriber = new DoctrineEncryptSubscriber($reader, $this->encryptor);
        $this->entityManager->getEventManager()->addEventSubscriber($this->subscriber);

        $schemaTool = new SchemaTool($this->entityManager);
        $classes    = $this->entityManager->getMetadataFactory()->getAllMetadata();
        $schemaTool->dropSchema($classes);
        $schemaTool->createSchema($classes);

        error_reporting(E_ALL);
    }

    public function testEncryptionHappensOnOnlyAnnotatedFields()
    {
        if (! extension_loaded('sodium')) {
            $this->markTestSkipped('This test only runs when the sodium extension is enabled.');
        }
        $secret    = "It's a secret";
        $notSecret = "You're all welcome to know this.";
        $em        = $this->entityManager;
        $owner     = new Owner();
        $owner->setSecret($secret);
        $owner->setNotSecret($notSecret);
        $em->persist($owner);
        $em->flush();
        $em->clear();
        unset($owner);

        $connection = $em->getConnection();
        $stmt       = $connection->prepare('SELECT * from owner WHERE id = ?');
        $owners     = $em->getRepository(Owner::class)->findAll();
        $this->assertCount(1, $owners);
        /** @var Owner $owner */
        $owner = $owners[0];
        $this->assertEquals($secret, $owner->getSecret());
        $this->assertEquals($notSecret, $owner->getNotSecret());
        $stmt->bindValue(1, $owner->getId());
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $this->assertEquals($notSecret, $result['notSecret']);
        $this->assertNotEquals($secret, $result['secret']);
        $this->assertStringEndsWith('<ENC>', $result['secret']);
        $decrypted = $this->encryptor->decrypt(str_replace('<ENC>', '', $result['secret']));
        $this->assertEquals($secret, $decrypted);
    }

    public function testEncryptionCascades()
    {
        if (! extension_loaded('sodium')) {
            $this->markTestSkipped('This test only runs when the sodium extension is enabled.');
        }
        $secret        = "It's a secret";
        $notSecret     = "You're all welcome to know this.";
        $em            = $this->entityManager;
        $owner         = new Owner();
        $em->persist($owner); // persist cascades
        $em->flush();

        $cascadeTarget = new CascadeTarget();
        $cascadeTarget->setSecret($secret);
        $cascadeTarget->setNotSecret($notSecret);
        $owner->setCascaded($cascadeTarget);
        $em->flush();
        $em->clear();
        unset($owner);
        unset($cascadeTarget);

        $connection     = $em->getConnection();
        $stmt           = $connection->prepare('SELECT * from cascadeTarget WHERE id = ?');
        $cascadeTargets = $em->getRepository(CascadeTarget::class)->findAll();
        $this->assertCount(1, $cascadeTargets);
        /** @var CascadeTarget $cascadeTarget */
        $cascadeTarget = $cascadeTargets[0];
        $this->assertEquals($secret, $cascadeTarget->getSecret());
        $this->assertEquals($notSecret, $cascadeTarget->getNotSecret());
        $stmt->bindValue(1, $cascadeTarget->getId());
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $this->assertEquals($notSecret, $result['notSecret']);
        $this->assertNotEquals($secret, $result['secret']);
        $this->assertStringEndsWith('<ENC>', $result['secret']);
        $decrypted = $this->encryptor->decrypt(str_replace('<ENC>', '', $result['secret']));
        $this->assertEquals($secret, $decrypted);
    }


    /**
     * @throws \Doctrine\DBAL\DBALException
     * @throws \Doctrine\ORM\OptimisticLockException
     */
    public function testEncryptionDoesNotHappenWhenThereIsNoChange()
    {
        if (! extension_loaded('sodium')) {
            $this->markTestSkipped('This test only runs when the sodium extension is enabled.');
        }
        $secret    = "It's a secret";
        $notSecret = "You're all welcome to know this.";
        $em        = $this->entityManager;
        $owner1     = new Owner();
        $owner1->setSecret($secret);
        $owner1->setNotSecret($notSecret);
        $em->persist($owner1);
        $owner2     = new Owner();
        $owner2->setSecret($secret);
        $owner2->setNotSecret($notSecret);
        $em->persist($owner2);

        $em->flush();
        $em->clear();
        $owner1Id = $owner1->getId();
        unset($owner1);
        unset($owner2);

        // test that it was encrypted correctly
        $connection = $em->getConnection();
        $stmt       = $connection->prepare('SELECT * from owner WHERE id = ?');
        $stmt->bindValue(1, $owner1Id);
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $originalEncryption = $result['secret'];
        $this->assertStringEndsWith('<ENC>', $originalEncryption); // is encrypted

        $owners = $em->getRepository(Owner::class)->findAll();
        /** @var Owner $owner */
        foreach ($owners as $owner) {
            $this->assertEquals($secret, $owner->getSecret());
            $this->assertEquals($notSecret, $owner->getNotSecret());
        }
        $stack = new DebugStack();
        $connection->getConfiguration()->setSQLLogger($stack);
        $this->assertCount(0, $stack->queries);
        $beforeFlush = $this->subscriber->encryptCounter;
        $em->flush();
        $afterFlush = $this->subscriber->encryptCounter;
        // No encryption should have happened because we didn't change anything.
        $this->assertEquals($beforeFlush, $afterFlush);
        // No queries happened because we didn't change anything.
        $this->assertCount(0, $stack->queries, "Unexpected queries:\n".var_export($stack->queries, true));

        // flush again
        $beforeFlush = $this->subscriber->encryptCounter;
        $em->flush();
        $afterFlush = $this->subscriber->encryptCounter;
        // No encryption should have happened because we didn't change anything.
        $this->assertEquals($beforeFlush, $afterFlush);
        // No queries happened because we didn't change anything.
        $this->assertCount(0, $stack->queries, "Unexpected queries:\n".var_export($stack->queries, true));

        $stmt->bindValue(1, $owner1Id);
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $shouldBeTheSameAsBefore = $result['secret'];
        $this->assertStringEndsWith('<ENC>', $shouldBeTheSameAsBefore); // is encrypted
        $this->assertEquals($originalEncryption, $shouldBeTheSameAsBefore);

    }

    public function testEncryptionDoesHappenWhenASecretIsChanged()
    {
        if (! extension_loaded('sodium')) {
            $this->markTestSkipped('This test only runs when the sodium extension is enabled.');
        }
        $secret    = "It's a secret";
        $notSecret = "You're all welcome to know this.";
        $em        = $this->entityManager;
        $owner     = new Owner();
        $owner->setSecret($secret);
        $owner->setNotSecret($notSecret);
        $em->persist($owner);
        $em->flush();
        $em->clear();
        $ownerId = $owner->getId();
        unset($owner);

        // test that it was encrypted correctly
        $connection = $em->getConnection();
        $stmt       = $connection->prepare('SELECT * from owner WHERE id = ?');
        $stmt->bindValue(1, $ownerId);
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $originalEncryption = $result['secret'];
        $this->assertStringEndsWith('<ENC>', $originalEncryption); // is encrypted

        /** @var Owner $owner */
        $owner = $em->getRepository(Owner::class)->find($ownerId);
        $owner->setSecret('A NEW SECRET!!!');
        $beforeFlush = $this->subscriber->encryptCounter;
        $em->flush();
        $afterFlush = $this->subscriber->encryptCounter;
        // No encryption should have happened because we didn't change anything.
        $this->assertGreaterThan($beforeFlush, $afterFlush);

        $stmt->bindValue(1, $ownerId);
        $stmt->execute();
        $results = $stmt->fetchAll();
        $this->assertCount(1, $results);
        $result = $results[0];
        $shouldBeDifferentFromBefore = $result['secret'];
        $this->assertStringEndsWith('<ENC>', $shouldBeDifferentFromBefore); // is encrypted
        $this->assertNotEquals($originalEncryption, $shouldBeDifferentFromBefore);

    }


    public function tearDown()
    {
        unlink($this->dbFile);
    }
}