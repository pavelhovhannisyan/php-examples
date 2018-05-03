public function cartAction(Request $request)
    {
        $this->breadcrumbs->addItem('Indkøbskurv');

        $user = $this->getUser();
        $couponError = '';
        $shoppingCart = $this->get('order_service')->getShoppingCart();

        if ($request->isMethod('post')) {
            if ($request->request->get('couponForm')) {
                $this->get('coupon_service')->applyCoupon($user, $request->request->get('coupon'), $shoppingCart, $couponError);

                if (empty($couponError)) {
                    return $this->redirectToRoute('checkout');
                }
            } else if ($request->request->get('subCustomerForm')) {
                $subCustomer = $this->em->getRepository('AppBundle:SubCustomer')->find($request->request->get('subCustomer'));
                $shoppingCart->setSubCustomer($subCustomer);

                $this->em->persist($shoppingCart);
                $this->em->flush();
            }
        }

        $subCustomers = null;
        if ($user and $customer = $user->getCustomer()) {
            $subCustomers = $this->em->getRepository('AppBundle:SubCustomer')->findByCustomer($customer);
        } 

        return $this->render('AppBundle:Order:cart.html.twig', [
            'shoppingCart'      => $shoppingCart,
            'couponError'       => $couponError,
            'subCustomers'      => $subCustomers
        ]);
    }