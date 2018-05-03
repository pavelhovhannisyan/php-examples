/**
     * Crate conversation
     * @param StoreNumber $storeNumber
     * @param StoreCustomer $customer
     * @param array $params
     * @param ILeadLog $ileadLog
     * @return Conversation
     * @internal param $message
     */
    private function createConversation(StoreNumber $storeNumber, StoreCustomer $customer, $params = array(), ILeadLog $ileadLog)
    {
        $conversation = new Conversation();
        $conversation->setStoreCustomer($customer);
        $conversation->setStoreNumber($storeNumber);
        $message = $this->removeClickPath($params['message']);
        $conversation->setBody($message);
        if (isset($params['reference'])) {
            $conversation->setReference($params['reference']);
        }
        if (isset($params['meta'])) {
            $conversation->setMeta($params['meta']);
        }
        $conversation->setMessageType('iLead');
        $conversation->setType('receive');
        $conversation->setILead($ileadLog);
        $this->em->persist($conversation);
        $customer->setLastMessage($conversation);
        $customer->setLastMessageAt(new \DateTime());
        $this->em->persist($customer);
        $this->em->flush();
        return $conversation;
    }
